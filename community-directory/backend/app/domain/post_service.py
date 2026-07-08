"""
Post service — orchestrates creating, listing, reporting, and resolving shared posts
and emergency alerts. Integrates rate-limiting and authorization checks.
"""
from typing import Any, Dict, List, Optional, Tuple
from bson import ObjectId

from app.core.errors import NotFound, ValidationError, PermissionDenied
from app.repositories.posts_repo import PostsRepository


class PostService:
    def __init__(self, db):
        self.db = db
        self.repo = PostsRepository(db)

    async def create_post(
        self,
        post_type: str,          # "INBOX" | "EMERGENCY"
        author_member_id: str,
        message: Optional[str] = None,
        media_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Validate post content, check media limits and ownership, and create post.
        Links media attachments to the created post.
        """
        message_val = message.strip() if message else ""
        has_message = len(message_val) > 0
        has_media = bool(media_ids and len(media_ids) > 0)
        
        if not has_message and not has_media:
            raise ValidationError("Post must contain either a message or media attachments.")

        # Media validations
        if media_ids:
            if len(media_ids) > 3:
                raise ValidationError("A post cannot have more than 3 media attachments.")
                
            from app.repositories.media_repo import MediaRepository
            media_repo = MediaRepository(self.db)
            
            for m_id in media_ids:
                try:
                    m_oid = ObjectId(m_id)
                except Exception:
                    raise NotFound(f"Media object {m_id} not found.")
                media = await media_repo.find_by_id(m_oid)
                if not media:
                    raise NotFound(f"Media object {m_id} not found.")
                if media["status"] != "CONFIRMED":
                    raise ValidationError(f"Media object {m_id} is not confirmed.")
                if media["owner_member_id"] != author_member_id:
                    raise PermissionDenied(f"You do not own media object {m_id}.")

        post_id = await self.repo.create_post(
            post_type=post_type,
            author_member_id=author_member_id,
            message=message_val,
            media_ids=media_ids,
        )

        # Link media to post
        if media_ids:
            for m_id in media_ids:
                await media_repo.link_to_post(ObjectId(m_id), post_id)
        
        created = await self.get_post_by_id(post_id)
        return created


    async def get_post_by_id(self, post_id: str) -> Dict[str, Any]:
        """Retrieve a single post by string ID."""
        try:
            oid = ObjectId(post_id)
        except Exception:
            raise NotFound("Post not found.")
            
        post = await self.repo.find_by_id(oid)
        if not post:
            raise NotFound("Post not found.")
        return post

    async def list_feed(
        self, post_type: str, page: int = 1, page_size: int = 20, status: Optional[str] = None
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        List posts of a given type. Returns (posts, total_count).
        Excludes REMOVED posts by default.
        """
        page = max(1, page)
        page_size = max(1, min(page_size, 100))
        
        docs = await self.repo.list_feed(post_type, page, page_size, status)
        
        if status:
            count_filter = status
        else:
            count_filter = {"$in": ["ACTIVE", "RESOLVED"]}
            
        total = await self.repo.collection.count_documents(
            {"type": post_type, "status": count_filter}
        )
        return docs, total

    async def report_post(self, post_id: str) -> bool:
        """Report a post for moderation. Increments report count."""
        try:
            oid = ObjectId(post_id)
        except Exception:
            raise NotFound("Post not found.")
            
        post = await self.repo.find_by_id(oid)
        if not post:
            raise NotFound("Post not found.")
            
        return await self.repo.report_post(oid)

    async def resolve_emergency(
        self, post_id: str, resolved_by: str, note: Optional[str] = None
    ) -> Dict[str, Any]:
        """Mark an emergency alert as resolved. Admin only. Logs audit log."""
        try:
            oid = ObjectId(post_id)
        except Exception:
            raise NotFound("Post not found.")
            
        post = await self.repo.find_by_id(oid)
        if not post or post["type"] != "EMERGENCY":
            raise NotFound("Emergency alert not found.")
            
        await self.repo.resolve_emergency(oid, resolved_by, note)
        
        from app.domain.audit_service import AuditService
        await AuditService(self.db).log(
            actor=resolved_by,
            action="EMERGENCY_RESOLVED",
            target=post_id,
            before={"status": post["status"]},
            after={"status": "RESOLVED", "note": note},
            reason=note,
        )
        
        resolved = await self.get_post_by_id(post_id)
        return resolved

    async def remove_post(self, post_id: str, actioned_by: str, reason: str) -> bool:
        """Soft-remove an Inbox or Emergency post for moderation. Admin only. Logs audit log."""
        try:
            oid = ObjectId(post_id)
        except Exception:
            raise NotFound("Post not found.")

        post = await self.repo.find_by_id(oid)
        if not post:
            raise NotFound("Post not found.")

        success = await self.repo.remove_post(oid, actioned_by, reason)
        if success:
            from app.domain.audit_service import AuditService
            await AuditService(self.db).log(
                actor=actioned_by,
                action="POST_REMOVED",
                target=post_id,
                before={"message": post.get("message"), "type": post["type"], "status": post["status"]},
                after={"status": "REMOVED", "reason": reason},
                reason=reason,
            )
        return success

