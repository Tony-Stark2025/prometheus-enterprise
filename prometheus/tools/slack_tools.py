"""
Slack and workstream communication tools for Prometheus.
Provides public workstream ingestion and Human-In-The-Loop (HITL) action drafting
via live Slack Web API with Firestore Vault & Secret Manager credential resolution.
Zero mock or synthetic fallback data.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

import httpx

from prometheus.config import settings
from prometheus.memory.state_store import state_store, ActionDraftRecord, DraftStatus
from prometheus.memory.firestore_store import firestore_store

logger = logging.getLogger(__name__)


class SlackTools:
    """
    Enterprise Slack Web API telemetry client and HITL action dispatcher.
    Ingests public communication context and dispatches interactive Block Kit action cards strictly upon human approval.
    """

    _user_cache: Dict[str, str] = {}
    _channel_cache: Dict[str, str] = {}
    _action_locks: Dict[Any, asyncio.Lock] = {}

    @classmethod
    def _get_lock(cls) -> asyncio.Lock:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop not in cls._action_locks:
            cls._action_locks[loop] = asyncio.Lock()
        return cls._action_locks[loop]

    @classmethod
    async def _resolve_credentials(
        cls,
        channel_names: Optional[List[str]] = None,
        tenant_id: str = "default_enterprise",
    ) -> Tuple[Optional[str], List[str]]:
        """Resolves Slack bot token and channel list from Firestore Vault or settings."""
        vault_cfg = await firestore_store.get_integration(tenant_id, "slack") or {}
        token = (
            vault_cfg.get("slack_bot_token")
            or vault_cfg.get("bot_token")
            or vault_cfg.get("token")
            or settings.slack_bot_token
        )
        raw_channels = (
            channel_names
            or vault_cfg.get("slack_channels")
            or vault_cfg.get("channels")
            or settings.slack_channels
        )
        if isinstance(raw_channels, str):
            target_channels = [c.strip() for c in raw_channels.split(",") if c.strip()]
        elif isinstance(raw_channels, list):
            target_channels = [str(c).strip() for c in raw_channels if str(c).strip()]
        else:
            target_channels = []
        return token, target_channels

    @classmethod
    def _get_headers(cls, token: Optional[str] = None) -> Dict[str, str]:
        resolved_token = token if token is not None else settings.slack_bot_token
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "Prometheus-Observability-Fleet/1.1",
        }
        if resolved_token:
            headers["Authorization"] = f"Bearer {resolved_token}"
        return headers

    @classmethod
    def _infer_scopes(cls, channel_name: str) -> List[str]:
        ch_lower = channel_name.lower()
        if "billing" in ch_lower or "finance" in ch_lower:
            return ["engineering", "finance"]
        elif "sec" in ch_lower or "auth" in ch_lower:
            return ["engineering", "platform", "security"]
        return ["engineering", "platform"]

    @classmethod
    async def _resolve_channel_id(
        cls, client: httpx.AsyncClient, channel_name: str, token: Optional[str] = None
    ) -> Optional[str]:
        clean_name = channel_name.lstrip("#").lower()
        if clean_name in cls._channel_cache:
            return cls._channel_cache[clean_name]

        try:
            url = "https://slack.com/api/conversations.list?types=public_channel,private_channel&exclude_archived=true&limit=100"
            resp = await client.get(url, headers=cls._get_headers(token))
            if resp.status_code == 200:
                data = resp.json()
                if data.get("ok"):
                    for ch in data.get("channels", []):
                        name = ch.get("name", "").lower()
                        ch_id = ch.get("id")
                        if name and ch_id:
                            cls._channel_cache[name] = ch_id
                            if name == clean_name:
                                return ch_id
        except Exception as e:
            logger.warning(f"Failed to resolve Slack channel '{channel_name}': {e}")
        return cls._channel_cache.get(clean_name, None)

    @classmethod
    async def _resolve_user_id(
        cls, client: httpx.AsyncClient, username: str, token: Optional[str] = None
    ) -> Optional[str]:
        clean_user = username.lstrip("@").lower().strip()
        if not clean_user:
            return None
        for uid, uname in cls._user_cache.items():
            if uname.lower() == clean_user:
                return uid

        try:
            url = "https://slack.com/api/users.list?limit=100"
            resp = await client.get(url, headers=cls._get_headers(token))
            if resp.status_code == 200:
                data = resp.json()
                if data.get("ok"):
                    for member in data.get("members", []):
                        uid = member.get("id")
                        uname = member.get("name", "")
                        dname = member.get("profile", {}).get("display_name", "")
                        rname = member.get("profile", {}).get("real_name", "")
                        email = member.get("profile", {}).get("email", "")

                        if uid:
                            resolved_name = dname or uname or uid
                            cls._user_cache[uid] = resolved_name
                            if (
                                uname.lower() == clean_user
                                or dname.lower() == clean_user
                                or clean_user in uname.lower()
                                or clean_user in (rname or "").lower()
                                or clean_user in (email or "").lower()
                            ):
                                return uid
        except Exception as e:
            logger.warning(f"Failed to resolve Slack user '{username}': {e}")
        return None

    @classmethod
    async def _resolve_username_by_id(
        cls, client: httpx.AsyncClient, user_id: str, token: Optional[str] = None
    ) -> str:
        if user_id in cls._user_cache:
            return cls._user_cache[user_id]

        try:
            url = f"https://slack.com/api/users.info?user={user_id}"
            resp = await client.get(url, headers=cls._get_headers(token))
            if resp.status_code == 200:
                data = resp.json()
                if data.get("ok"):
                    user = data.get("user", {})
                    name = user.get("name", "")
                    dname = user.get("profile", {}).get("display_name", "")
                    resolved = dname or name or user_id
                    cls._user_cache[user_id] = resolved
                    return resolved
        except Exception:
            pass

        return user_id if user_id != "unknown" else "unknown"

    @classmethod
    async def get_recent_channel_messages(
        cls,
        scopes: Optional[List[str]] = None,
        channel_names: Optional[List[str]] = None,
        tenant_id: str = "default_enterprise",
    ) -> List[Dict[str, Any]]:
        """
        Ingests recent messages from configured Slack channels via live Slack Web API.
        Returns an empty list if Slack credentials are not configured or API fails.
        """
        token, target_channels = await cls._resolve_credentials(
            channel_names=channel_names, tenant_id=tenant_id
        )
        if not token or not target_channels:
            logger.info("Slack credentials or channels not configured; returning empty message list.")
            return []

        live_messages: List[Dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                for ch_name in target_channels:
                    clean_ch_name = ch_name.lstrip("#")
                    ch_id = await cls._resolve_channel_id(client, clean_ch_name, token) or clean_ch_name
                    url = f"https://slack.com/api/conversations.history?channel={ch_id}&limit=20"
                    resp = await client.get(url, headers=cls._get_headers(token))

                    if resp.status_code == 429:
                        logger.warning("Slack API rate limit encountered.")
                        break

                    if resp.status_code != 200:
                        continue

                    data = resp.json()
                    if not data.get("ok"):
                        if data.get("error") == "ratelimited":
                            logger.warning("Slack API returned ratelimited error.")
                            break
                        continue

                    raw_messages = data.get("messages", [])
                    valid_msgs = [m for m in raw_messages if m.get("subtype") not in ("channel_join", "channel_leave", "bot_message")]
                    unique_users = list({m.get("user") for m in valid_msgs if m.get("user")})
                    if unique_users:
                        resolved_list = await asyncio.gather(*[cls._resolve_username_by_id(client, uid, token) for uid in unique_users])
                        user_map = dict(zip(unique_users, resolved_list))
                    else:
                        user_map = {}

                    for msg in valid_msgs:
                        user_id = msg.get("user", "unknown")
                        username = user_map.get(user_id, user_id)
                        text = msg.get("text", "")
                        inferred_scopes = cls._infer_scopes(f"{clean_ch_name} {text}")

                        live_messages.append({
                            "id": f"MSG-{msg.get('ts', '').replace('.', '')[:10]}",
                            "channel": f"#{clean_ch_name}",
                            "user": username,
                            "timestamp": datetime.fromtimestamp(
                                float(msg.get("ts", 0)), tz=timezone.utc
                            ).isoformat() if msg.get("ts") else datetime.now(timezone.utc).isoformat(),
                            "text": text,
                            "content": text,
                            "topic": f"Discussion in #{clean_ch_name}",
                            "scopes": inferred_scopes,
                        })

        except Exception as exc:
            logger.error(f"Live Slack ingestion failed: {exc}")
            return []

        if scopes:
            return [m for m in live_messages if any(s in m.get("scopes", []) for s in scopes)]
        return live_messages

    @classmethod
    async def draft_action_card(
        cls,
        target: str,
        action_type: str,
        content: str,
        context_blocker_id: Optional[str] = None,
        require_confirmation: bool = True,
    ) -> ActionDraftRecord:
        """
        Creates a proposed action draft requiring explicit human sign-off before dispatch.
        Deduplicates against existing PENDING drafts for the same blocker, target, and action_type.
        """
        if context_blocker_id:
            existing_pending = await state_store.list_drafts(status=DraftStatus.PENDING)
            for existing in existing_pending:
                if (
                    existing.context_blocker_id == context_blocker_id
                    and existing.target_channel_or_user == target
                    and existing.action_type == action_type
                ):
                    updated = await state_store.update_draft_content(
                        draft_id=existing.draft_id,
                        content=content,
                        target=target,
                    )
                    return updated or existing

        draft_id = f"DRAFT-{int(datetime.now(timezone.utc).timestamp() * 1000)}-{uuid.uuid4().hex[:6]}"
        draft = ActionDraftRecord(
            draft_id=draft_id,
            target_channel_or_user=target,
            action_type=action_type,
            content=content,
            context_blocker_id=context_blocker_id,
            status=DraftStatus.PENDING,
            metadata={
                "require_confirmation": require_confirmation,
                "created_by": "ActionDrafterAgent",
            },
        )
        await state_store.save_draft(draft)
        return draft

    @classmethod
    async def dispatch_approved_action(
        cls,
        draft_id: str,
        approver_username: str,
        tenant_id: str = "default_enterprise",
    ) -> Dict[str, Any]:
        async with cls._get_lock():
            draft = await state_store.get_draft(draft_id)
            if not draft:
                raise ValueError(f"Draft '{draft_id}' not found.")

            if draft.status == DraftStatus.EXECUTED:
                return {"status": "already_executed", "draft_id": draft_id}

            token, _ = await cls._resolve_credentials(tenant_id=tenant_id)
            result_message: str

            if token:
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        target = draft.target_channel_or_user
                        target_channel_id: Optional[str] = None

                        if target.startswith("#"):
                            target_channel_id = await cls._resolve_channel_id(client, target.lstrip("#"), token)
                        elif target.startswith("@") or not target.startswith("C"):
                            user_id = await cls._resolve_user_id(client, target.lstrip("@"), token)
                            if user_id:
                                open_resp = await client.post(
                                    "https://slack.com/api/conversations.open",
                                    headers=cls._get_headers(token),
                                    json={"users": user_id},
                                )
                                if open_resp.status_code == 200 and open_resp.json().get("ok"):
                                    target_channel_id = open_resp.json().get("channel", {}).get("id")

                        post_url = "https://slack.com/api/chat.postMessage"
                        post_payload: Dict[str, Any] = {
                            "channel": target_channel_id or target,
                            "text": draft.content,
                        }
                        if draft.metadata and "slack_blocks" in draft.metadata:
                            post_payload["blocks"] = draft.metadata["slack_blocks"]

                        post_resp = await client.post(post_url, headers=cls._get_headers(token), json=post_payload)
                        post_data = post_resp.json() if post_resp.status_code == 200 else {}

                        if post_data.get("ok"):
                            msg_ts = post_data.get("ts", "")
                            result_message = (
                                f"Successfully dispatched '{draft.action_type}' to '{target}' via Slack API "
                                f"(ts: {msg_ts}, Approved by {approver_username})."
                            )
                        else:
                            slack_err = post_data.get("error", f"HTTP_{post_resp.status_code}")
                            result_message = (
                                f"Slack API returned '{slack_err}' for '{target}' "
                                f"(Approved by {approver_username})."
                            )
                except Exception as exc:
                    logger.error(f"Live Slack dispatch exception: {exc}")
                    result_message = (
                        f"Slack API transport error ({exc}) while dispatching '{draft.action_type}' to '{draft.target_channel_or_user}' "
                        f"(Approved by {approver_username})."
                    )
            else:
                result_message = (
                    f"Approved '{draft.action_type}' for '{draft.target_channel_or_user}' "
                    f"(Approved by {approver_username}; Slack token unconfigured)."
                )

            await state_store.update_draft_status(
                draft_id=draft_id,
                status=DraftStatus.EXECUTED,
                approver=approver_username,
                result=result_message,
            )
            return {
                "status": "success",
                "draft_id": draft_id,
                "target": draft.target_channel_or_user,
                "result": result_message,
            }
