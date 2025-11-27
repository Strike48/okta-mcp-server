"""Connection monitoring middleware for graceful client disconnect handling."""

import logging
from contextvars import ContextVar
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.exceptions import ToolError
import anyio

logger = logging.getLogger("okta_mcp_server")

# Context variables to store per-request Okta credentials
okta_org_url_context: ContextVar[str | None] = ContextVar('okta_org_url', default=None)
okta_api_token_context: ContextVar[str | None] = ContextVar('okta_api_token', default=None)

class ConnectionMonitorMiddleware(Middleware):
    """Middleware that handles client disconnections gracefully to keep server healthy."""
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Handle tool execution with graceful disconnect detection."""
        
        tool_name = context.message.name
        logger.debug(f"Starting tool execution: {tool_name}")
        
        try:
            # Execute the tool
            result = await call_next(context)
            logger.debug(f"Tool {tool_name} completed successfully")
            return result
            
        except anyio.ClosedResourceError:
            # This is the critical fix - catch client disconnects at middleware level
            logger.warning(f"Client disconnected during {tool_name}. Server remains healthy.")
            # Don't try to return anything - the connection is gone
            return None
            
        except Exception as e:
            logger.error(f"Error in tool {tool_name}: {e}")
            # Re-raise other exceptions normally
            raise

class RateLimitHandlingMiddleware(Middleware):
    """Middleware that converts Okta rate limits to user-friendly errors."""
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Convert rate limit errors to immediate user-friendly responses."""
        
        try:
            return await call_next(context)
            
        except Exception as e:
            error_msg = str(e).lower()
            
            # Check if this is an Okta rate limit error
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                tool_name = context.message.name
                logger.warning(f"Rate limit hit for tool {tool_name}")
                raise ToolError(
                    f"Okta API rate limit exceeded. Please wait a moment and try again. "
                    f"This typically happens when making many requests quickly."
                )
            
            # Re-raise other exceptions
            raise


class OktaHeaderAuthMiddleware(Middleware):
    """Middleware that extracts Okta credentials from HTTP headers.
    
    This allows passing Okta credentials per-request via HTTP headers:
    - X-Okta-Token: API token for authentication
    - X-Okta-Domain: Okta organization URL (e.g., https://your-org.okta.com)
    
    Credentials in headers take precedence over environment variables.
    """
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Extract Okta credentials from headers and store in context."""
        
        headers_lower = {}
        
        # Access headers from FastMCP context -> request_context -> request (Starlette)
        try:
            if context.fastmcp_context and context.fastmcp_context.request_context:
                request = context.fastmcp_context.request_context.request
                if request and hasattr(request, 'headers'):
                    # Starlette headers - make case-insensitive
                    headers_lower = {k.lower(): v for k, v in request.headers.items()}
                    logger.debug(f"Extracted {len(headers_lower)} headers from request")
        except Exception as e:
            logger.debug(f"Error extracting headers: {e}")
        
        # Look for Okta credentials in headers
        okta_token = headers_lower.get('x-okta-token')
        okta_domain = headers_lower.get('x-okta-domain')
        
        # Store credentials in context vars if present
        token_token = None
        domain_token = None
        
        if okta_token:
            logger.info("Using Okta credentials from X-Okta-Token header")
            token_token = okta_api_token_context.set(okta_token)
        
        if okta_domain:
            logger.info(f"Using Okta domain from X-Okta-Domain header: {okta_domain}")
            domain_token = okta_org_url_context.set(okta_domain)
        
        try:
            # Execute the tool with credentials in context
            return await call_next(context)
        finally:
            # Clean up context vars
            if token_token is not None:
                okta_api_token_context.reset(token_token)
            if domain_token is not None:
                okta_org_url_context.reset(domain_token)