"""Enhanced Access analysis tools for Okta MCP server."""

import logging
import anyio
from typing import List, Dict, Any, Optional
from fastmcp import FastMCP, Context
from pydantic import Field

from okta_mcp.utils.okta_client import OktaMcpClient
from okta_mcp.utils.error_handling import handle_okta_result
from okta_mcp.utils.normalize_okta_responses import normalize_okta_response

logger = logging.getLogger("okta_mcp_server")

def register_access_analysis_tools(server: FastMCP, okta_client: OktaMcpClient):
    """Register access analysis tools with the MCP server.
    
    Args:
        server: The FastMCP server instance
        okta_client: The Okta client wrapper
    """
    
    @server.tool()
    async def analyze_user_app_access(
        app_identifier: str = Field(..., description="Application name, label, or Okta ID (required)"),
        user_identifier: str = Field(default="", description="User email, login, or Okta ID (optional if group_identifier provided)"),
        group_identifier: str = Field(default="", description="Group name or Okta ID (optional if user_identifier provided)"),
        ctx: Context = None
    ) -> Dict[str, Any]:
        """Comprehensive access analysis for users and applications.
        
        SPECIAL TOOL: Collects ALL access-related data including user details, assignments, 
        application info, policy rules, MFA factors, and network zones. Returns comprehensive 
        raw data for LLM analysis without making access decisions.
        
        The LLM MUST analyze the returned data and provide clear access determination with 
        specific reasoning based on user status, application assignments, and policy rule evaluation.
        
        Parameters:
        - app_identifier: Application name, label, or Okta ID (REQUIRED)
        - user_identifier: User email, login, or ID (optional if group provided)
        - group_identifier: Group name or ID (optional if user provided)
        
        Note: Either user_identifier OR group_identifier must be provided.
        
        Returns comprehensive analysis data including:
        • User details (if user specified): status, profile, MFA factors
        • Group details (if group specified): name, description, type
        • Application details: status, sign-on mode, access policy
        • Assignment status: direct or group-based assignments
        • Policy rules: access conditions, network zones, MFA requirements with detailed zone/user/group info
        • Network zones: IP ranges, gateway details for policy evaluation
        
        The tool collects raw data only - access decisions must be made by analyzing:
        1. User/Group must be ACTIVE
        2. User/Group must be assigned to application (directly or via group)
        3. All policy rules must be satisfied (network zones, MFA, etc.)
        
        Examples:
        • analyze_user_app_access(app_identifier="Salesforce", user_identifier="john@company.com")
        • analyze_user_app_access(app_identifier="Office 365", group_identifier="Sales Team")
        • analyze_user_app_access(app_identifier="0oa1bc2def3ghi4jk5l6", user_identifier="00u1abc2def3ghi4jk5")
        """
        try:
            if ctx:
                logger.info(f"SERVER: Executing analyze_user_app_access with app={app_identifier}, user={user_identifier}, group={group_identifier}")
            
            # Validate input parameters
            if not app_identifier or not app_identifier.strip():
                raise ValueError("app_identifier is required")
            
            app_identifier = app_identifier.strip()
            user_identifier = user_identifier.strip() if user_identifier else None
            group_identifier = group_identifier.strip() if group_identifier else None
            
            if not user_identifier and not group_identifier:
                raise ValueError("Either user_identifier or group_identifier must be provided")
            
            if ctx:
                logger.info(f"Validation passed - starting access analysis")
                await ctx.report_progress(10, 100)
            
            result = {
                "status": "analyzing",
                "tool": "access_analysis",
                "query_parameters": {
                    "user_identifier": user_identifier,
                    "group_identifier": group_identifier,
                    "app_identifier": app_identifier
                }
            }
            
            # Step 1: Find the application
            if ctx:
                logger.info(f"Step 1: Finding application '{app_identifier}'")
                await ctx.report_progress(20, 100)
            
            app = await find_application(okta_client, app_identifier)
            if not app:
                return {
                    "status": "success",
                    "result_type": "application_not_found",
                    "entity": "application",
                    "id": app_identifier,
                    "tool": "access_analysis",
                    "message": f"Application '{app_identifier}' not found. The application name must match exactly (case sensitive) as shown in Okta Admin Portal, or it may be a privileged app like 'Okta Admin Console' that cannot be queried via API.",
                    "error": f"Application '{app_identifier}' not found in Okta org",
                    "can_access": False,
                    "reason": "Application not found - name must match exactly (case sensitive) or may be privileged app"
                }
            
            result["application_details"] = {
                "id": app.get("id"),
                "name": app.get("name"),
                "label": app.get("label"),
                "status": app.get("status"),
                "signOnMode": app.get("signOnMode")
            }
            
            # Extract access policy ID from _links if available
            access_policy_id = None
            access_policy_href = app.get("_links", {}).get("accessPolicy", {}).get("href")
            if access_policy_href and "/" in access_policy_href:
                access_policy_id = access_policy_href.split("/")[-1]
                result["application_details"]["accessPolicyID"] = access_policy_id
            
            if ctx:
                logger.info(f"Application found: {app.get('id')} - {app.get('label')}")
                await ctx.report_progress(40, 100)
            
            # Step 2: Process User or Group
            if user_identifier:
                if ctx:
                    logger.info(f"Step 2: Finding user '{user_identifier}'")
                
                user = await find_user(okta_client, user_identifier)
                if not user:
                    return {
                        "status": "success",
                        "result_type": "user_not_found",
                        "entity": "user",
                        "id": user_identifier,
                        "tool": "access_analysis",
                        "message": f"User '{user_identifier}' not found. Please verify the email address or username is correct.",
                        "error": f"User '{user_identifier}' not found in Okta org",
                        "can_access": False,
                        "reason": "User not found - verify email address or username is correct"
                    }
                
                result["user_details"] = {
                    "id": user.get("id"),
                    "email": user.get("profile", {}).get("email"),
                    "login": user.get("profile", {}).get("login"),
                    "firstName": user.get("profile", {}).get("firstName"),
                    "lastName": user.get("profile", {}).get("lastName"),
                    "status": user.get("status")
                }
                
                user_id = user.get("id")
                
                # Get user's MFA factors
                try:
                    raw_response = await okta_client.client.list_factors(user_id)
                    factors, resp, err = normalize_okta_response(raw_response)
                    
                    if not err and factors:
                        result["users_registered_factors"] = []
                        for factor in factors:
                            factor_dict = factor.to_dict() if hasattr(factor, 'to_dict') else factor
                            result["users_registered_factors"].append({
                                "id": factor_dict.get("id"),
                                "type": factor_dict.get("factorType"),
                                "provider": factor_dict.get("provider"),
                                "status": factor_dict.get("status"),
                                "name": factor_dict.get("profile", {}).get("name", "")
                            })
                    else:
                        result["users_registered_factors"] = []
                        
                except Exception as e:
                    logger.warning(f"Could not fetch MFA factors for user {user_id}: {str(e)}")
                    result["users_registered_factors"] = []
                    
            elif group_identifier:
                if ctx:
                    logger.info(f"Step 2: Finding group '{group_identifier}'")
                
                group = await find_group(okta_client, group_identifier)
                if not group:
                    return {
                        "status": "success",
                        "result_type": "group_not_found",
                        "entity": "group",
                        "id": group_identifier,
                        "tool": "access_analysis",
                        "message": f"Group '{group_identifier}' not found. The group name must exactly match the group name in Okta (case sensitive).",
                        "error": f"Group '{group_identifier}' not found in Okta org",
                        "can_access": False,
                        "reason": "Group not found - name must exactly match group name in Okta (case sensitive)"
                    }
                
                result["group_details"] = {
                    "id": group.get("id"),
                    "name": group.get("profile", {}).get("name"),
                    "description": group.get("profile", {}).get("description"),
                    "type": group.get("type")
                }
            
            if ctx:
                await ctx.report_progress(60, 100)
            
            # Step 3: Check assignments and policies
            app_id = app.get("id")
            
            if user_identifier:
                user_id = result["user_details"]["id"]
                assignment_result = await check_user_app_assignment(okta_client, app_id, user_id)
                result["assignment"] = assignment_result
            elif group_identifier:
                group_id = result["group_details"]["id"]
                assignment_result = await check_group_app_assignment(okta_client, app_id, group_id)
                result["assignment"] = assignment_result
            
            if ctx:
                await ctx.report_progress(80, 100)
            
            # Get application access policy if available with enhanced details
            if access_policy_id:
                try:
                    # Get policy details
                    raw_response = await okta_client.client.get_policy(access_policy_id)
                    policy, resp, err = normalize_okta_response(raw_response)
                    
                    if not err and policy:
                        policy_dict = policy.to_dict() if hasattr(policy, 'to_dict') else policy
                        result["access_policy"] = {
                            "id": policy_dict.get("id"),
                            "name": policy_dict.get("name"),
                            "status": policy_dict.get("status"),
                            "type": policy_dict.get("type")
                        }
                        
                        # Get policy rules with enhanced details
                        raw_response = await okta_client.client.list_policy_rules(access_policy_id)
                        rules, resp, err = normalize_okta_response(raw_response)
                        
                        if not err and rules:
                            result["policy_rules"] = []
                            
                            for rule in rules:
                                rule_dict = rule.to_dict() if hasattr(rule, 'to_dict') else rule
                                
                                rule_info = {
                                    "id": rule_dict.get("id"),
                                    "name": rule_dict.get("name"),
                                    "status": rule_dict.get("status"),
                                    "priority": rule_dict.get("priority"),
                                    "system": rule_dict.get("system", False)
                                }
                                
                                # Extract rule conditions with enhanced details
                                conditions = rule_dict.get("conditions", {})
                                if conditions:
                                    # Network zones - fetch and inject zone details directly
                                    if "network" in conditions:
                                        network_conditions = conditions.get("network", {})
                                        enhanced_network_conditions = network_conditions.copy()
                                        
                                        # Fetch and inject zone details for both include and exclude
                                        if network_conditions.get("connection") == "ZONE":
                                            # Process include zones - replace original include array with detailed objects
                                            if "include" in network_conditions:
                                                enhanced_include = []
                                                for zone_id in network_conditions.get("include", []):
                                                    zone_details = await fetch_zone_details(okta_client, zone_id)
                                                    enhanced_include.append({
                                                        "zone_id": zone_id,
                                                        "zone_details": zone_details
                                                    })
                                                enhanced_network_conditions["include"] = enhanced_include
                                            
                                            # Process exclude zones - replace original exclude array with detailed objects
                                            if "exclude" in network_conditions:
                                                enhanced_exclude = []
                                                for zone_id in network_conditions.get("exclude", []):
                                                    zone_details = await fetch_zone_details(okta_client, zone_id)
                                                    enhanced_exclude.append({
                                                        "zone_id": zone_id,
                                                        "zone_details": zone_details
                                                    })
                                                enhanced_network_conditions["exclude"] = enhanced_exclude
                                        
                                        rule_info["network_conditions"] = enhanced_network_conditions
                                    
                                    # User conditions - fetch and inject user details
                                    if "people" in conditions:
                                        people_conditions = conditions.get("people", {})
                                        enhanced_people_conditions = people_conditions.copy()
                                        
                                        # Process users in include list - replace original include array with detailed objects
                                        if "users" in people_conditions and "include" in people_conditions["users"]:
                                            enhanced_include_users = []
                                            for user_id in people_conditions["users"].get("include", []):
                                                user_details = await fetch_user_details(okta_client, user_id)
                                                enhanced_include_users.append({
                                                    "user_id": user_id,
                                                    "user_details": user_details
                                                })
                                            if "users" not in enhanced_people_conditions:
                                                enhanced_people_conditions["users"] = {}
                                            enhanced_people_conditions["users"]["include"] = enhanced_include_users
                                        
                                        # Process users in exclude list - replace original exclude array with detailed objects
                                        if "users" in people_conditions and "exclude" in people_conditions["users"]:
                                            enhanced_exclude_users = []
                                            for user_id in people_conditions["users"].get("exclude", []):
                                                user_details = await fetch_user_details(okta_client, user_id)
                                                enhanced_exclude_users.append({
                                                    "user_id": user_id,
                                                    "user_details": user_details
                                                })
                                            if "users" not in enhanced_people_conditions:
                                                enhanced_people_conditions["users"] = {}
                                            enhanced_people_conditions["users"]["exclude"] = enhanced_exclude_users
                                        
                                        # Process groups in include list - replace original include array with detailed objects
                                        if "groups" in people_conditions and "include" in people_conditions["groups"]:
                                            enhanced_include_groups = []
                                            for group_id in people_conditions["groups"].get("include", []):
                                                group_details = await fetch_group_details(okta_client, group_id)
                                                enhanced_include_groups.append({
                                                    "group_id": group_id,
                                                    "group_details": group_details
                                                })
                                            if "groups" not in enhanced_people_conditions:
                                                enhanced_people_conditions["groups"] = {}
                                            enhanced_people_conditions["groups"]["include"] = enhanced_include_groups
                                        
                                        # Process groups in exclude list - replace original exclude array with detailed objects
                                        if "groups" in people_conditions and "exclude" in people_conditions["groups"]:
                                            enhanced_exclude_groups = []
                                            for group_id in people_conditions["groups"].get("exclude", []):
                                                group_details = await fetch_group_details(okta_client, group_id)
                                                enhanced_exclude_groups.append({
                                                    "group_id": group_id,
                                                    "group_details": group_details
                                                })
                                            if "groups" not in enhanced_people_conditions:
                                                enhanced_people_conditions["groups"] = {}
                                            enhanced_people_conditions["groups"]["exclude"] = enhanced_exclude_groups
                                        
                                        rule_info["people_conditions"] = enhanced_people_conditions
                                    
                                    # Device conditions
                                    if "device" in conditions:
                                        rule_info["device_conditions"] = conditions.get("device", {})
                                
                                # Extract authentication requirements
                                actions = rule_dict.get("actions", {})
                                if actions and "appSignOn" in actions:
                                    app_sign_on = actions.get("appSignOn", {})
                                    
                                    # Access type (ALLOW/DENY)
                                    rule_info["access"] = app_sign_on.get("access")
                                    
                                    # Verification requirements
                                    if "verificationMethod" in app_sign_on:
                                        verification = app_sign_on.get("verificationMethod", {})
                                        rule_info["verification_method"] = {
                                            "factorMode": verification.get("factorMode"),
                                            "type": verification.get("type"),
                                            "constraints": verification.get("constraints", [])
                                        }
                                
                                result["policy_rules"].append(rule_info)
                
                except Exception as e:
                    result["policy_error"] = str(e)
            
            # Add comprehensive analysis notes for LLM with enhanced network zone explanations
            result["notes_must_read"] = {
                "access_determination_logic": "To determine if a user can access an application, analyze ALL the following conditions in order: 1) User must be ACTIVE (status='ACTIVE'), 2) User must be assigned to application either directly OR via group membership, 3) All policy rules must be satisfied including network zones and MFA requirements",
                
                "json_key_mapping": {
                    "user_details.status": "User account status - must be 'ACTIVE' for access",
                    "application_details.status": "Application status - must be 'ACTIVE' for access", 
                    "assignment.is_assigned": "True if user has access via direct or group assignment",
                    "assignment.assignment_type": "How user gets access: 'direct' or 'group'",
                    "assignment.via_groups": "List of groups that grant the user access to this app",
                    "users_registered_factors": "MFA factors user has enrolled (SMS, TOTP, PUSH, etc.)",
                    "policy_rules": "Access policy rules that define conditions for app access",
                    "policy_rules[].access": "'ALLOW' or 'DENY' - determines if rule grants or blocks access",
                    "policy_rules[].priority": "Lower number = higher priority rule",
                    "policy_rules[].verification_method.factorMode": "'1FA' (password only) or '2FA' (password + MFA factor required)",
                    "policy_rules[].network_conditions.include[].zone_details": "Detailed network zone info for zones that grant access in this rule",
                    "policy_rules[].network_conditions.exclude[].zone_details": "Detailed network zone info for zones that deny access in this rule",
                    "policy_rules[].people_conditions.users.include[].user_details": "Users explicitly granted access in this rule with full details",
                    "policy_rules[].people_conditions.users.exclude[].user_details": "Users explicitly denied access in this rule with full details", 
                    "policy_rules[].people_conditions.groups.include[].group_details": "Groups explicitly granted access in this rule with full details",
                    "policy_rules[].people_conditions.groups.exclude[].group_details": "Groups explicitly denied access in this rule with full details"
                },
                
                "network_zone_ip_evaluation": {
                    "gateways_definition": "GATEWAYS are the 'final' IP addresses that act as decision endpoints for network zone evaluation. These are the trusted IP ranges (CIDR blocks) or specific IPs that Okta considers as the authoritative source location for access decisions",
                    "proxies_definition": "PROXIES are trusted intermediary IP addresses that Okta's threat scorer will SKIP OVER when determining the user's actual location. When a request comes through these proxy IPs, Okta looks at the next IP in the X-Forwarded-For chain to find the real client IP",
                    "gateway_evaluation_logic": "When evaluating network zones, Okta compares the user's effective IP address against the GATEWAY ranges. If the IP matches a gateway range in an 'include' zone, the user is considered inside that network zone. If it matches an 'exclude' zone gateway, they are blocked",
                    "proxy_chain_logic": "If a request comes from a PROXY IP address, Okta does not use that IP for zone evaluation. Instead, it examines the X-Forwarded-For header to find the next IP in the chain (the actual client IP behind the proxy) and evaluates that IP against the gateway ranges",
                    "practical_example": "Example: User connects from IP 192.168.1.100 → Corporate Proxy 203.0.113.50 → Internet. If 203.0.113.50 is listed in proxies[], Okta ignores it and evaluates 192.168.1.100 against the gateway ranges to determine zone membership"
                },
                
                "response_format_instructions": "Provide clear explanation like: 'User [Name] can/cannot access [App] because: [specific reasons based on status, assignment, and policy evaluation]. For conditional access, specify network zones and MFA requirements clearly.'"
            }
            
            result["status"] = "success"
            
            if ctx:
                logger.info(f"Access analysis completed successfully")
                await ctx.report_progress(100, 100)
            
            return result
            
        except anyio.ClosedResourceError:
            logger.warning("Client disconnected during analyze_user_app_access. Server remains healthy.")
            return None
            
        except Exception as e:
            # Check for rate limit
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                logger.warning("Rate limit hit in analyze_user_app_access")
                return {
                    'error': 'rate_limit',
                    'message': 'Okta API rate limit exceeded. Please wait a moment and try again.',
                    'tool': 'analyze_user_app_access'
                }
            
            logger.exception("Error in analyze_user_app_access tool")
            return handle_okta_result(e, "analyze_user_app_access")


async def fetch_zone_details(okta_client: OktaMcpClient, zone_id: str) -> Dict[str, Any]:
    """Fetch detailed information for a network zone."""
    try:
        raw_response = await okta_client.client.get_network_zone(zone_id)
        zone, resp, err = normalize_okta_response(raw_response)
        
        if not err and zone:
            zone_dict = zone.to_dict() if hasattr(zone, 'to_dict') else zone
            return {
                "id": zone_dict.get("id", zone_id),
                "name": zone_dict.get("name", f"Zone {zone_id}"),
                "type": zone_dict.get("type", "UNKNOWN"),
                "status": zone_dict.get("status", "UNKNOWN"),
                "usage": zone_dict.get("usage", "UNKNOWN"),
                "gateways": zone_dict.get("gateways", []),
                "proxies": zone_dict.get("proxies", [])
            }
        
        return {"error": f"Failed to fetch zone details: {err}"}
        
    except Exception as e:
        return {"error": str(e)}


async def fetch_user_details(okta_client: OktaMcpClient, user_id: str) -> Dict[str, Any]:
    """Fetch detailed information for a user."""
    try:
        raw_response = await okta_client.client.get_user(user_id)
        user, resp, err = normalize_okta_response(raw_response)
        
        if not err and user:
            user_dict = user.to_dict() if hasattr(user, 'to_dict') else user
            profile = user_dict.get("profile", {})
            return {
                "id": user_dict.get("id", user_id),
                "email": profile.get("email", "No email"),
                "login": profile.get("login", "No login"),
                "firstName": profile.get("firstName", ""),
                "lastName": profile.get("lastName", ""),
                "displayName": f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip() or profile.get("email", user_id),
                "status": user_dict.get("status", "UNKNOWN")
            }
        else:
            return {"error": f"API call failed: {err}"}
        
    except Exception as e:
        return {"error": str(e)}


async def fetch_group_details(okta_client: OktaMcpClient, group_id: str) -> Dict[str, Any]:
    """Fetch detailed information for a group."""
    try:
        raw_response = await okta_client.client.get_group(group_id)
        group, resp, err = normalize_okta_response(raw_response)
        
        if not err and group:
            group_dict = group.to_dict() if hasattr(group, 'to_dict') else group
            profile = group_dict.get("profile", {})
            return {
                "id": group_dict.get("id", group_id),
                "name": profile.get("name", f"Group {group_id[-8:]}"),
                "description": profile.get("description", "No description"),
                "type": group_dict.get("type", "OKTA_GROUP"),
                "displayName": profile.get("name", f"Group {group_id[-8:]}"),
                "created": group_dict.get("created"),
                "lastUpdated": group_dict.get("lastUpdated"),
                "lastMembershipUpdated": group_dict.get("lastMembershipUpdated"),
                "objectClass": group_dict.get("objectClass", [])
            }
        else:
            return {
                "id": group_id,
                "name": f"Group {group_id[-8:]}",
                "description": "Group details unavailable",
                "type": "UNKNOWN",
                "displayName": f"Group {group_id[-8:]}",
                "error": f"API call failed: {err}"
            }
        
    except Exception as e:
        return {
            "id": group_id,
            "name": f"Group {group_id[-8:]}",
            "description": "Group details unavailable - exception occurred",
            "type": "UNKNOWN", 
            "displayName": f"Group {group_id[-8:]}",
            "error": str(e)
        }


async def find_application(okta_client: OktaMcpClient, app_identifier: str) -> Optional[Dict[str, Any]]:
    """Find application by ID, name, or label using OktaMcpClient."""
    
    # Try direct lookup by ID first if it looks like an Okta ID
    if app_identifier.startswith("0oa"):
        try:
            raw_response = await okta_client.client.get_application(app_identifier)
            app, resp, err = normalize_okta_response(raw_response)
            if not err and app:
                return app.to_dict() if hasattr(app, 'to_dict') else app
        except Exception:
            pass
    
    # Search by query parameter
    try:
        raw_response = await okta_client.client.list_applications({"q": app_identifier})
        apps, resp, err = normalize_okta_response(raw_response)
        
        if not err and apps:
            # Look for exact match first
            for app in apps:
                app_dict = app.to_dict() if hasattr(app, 'to_dict') else app
                label = app_dict.get("label", "").lower()
                name = app_dict.get("name", "").lower()
                search_term = app_identifier.lower()
                if label == search_term or name == search_term:
                    return app_dict
            
            # Return first match if no exact match
            first_app = apps[0]
            return first_app.to_dict() if hasattr(first_app, 'to_dict') else first_app
            
    except Exception:
        pass
    
    # Final attempt: list all and search
    try:
        raw_response = await okta_client.client.list_applications({})
        apps, resp, err = normalize_okta_response(raw_response)
        
        if not err and apps:
            search_term = app_identifier.lower()
            
            # Search for partial matches
            for app in apps:
                app_dict = app.to_dict() if hasattr(app, 'to_dict') else app
                label = app_dict.get("label", "").lower()
                name = app_dict.get("name", "").lower()
                
                if (search_term in label or search_term in name or
                    label in search_term or name in search_term):
                    return app_dict
                    
    except Exception:
        pass
    
    return None


async def find_user(okta_client: OktaMcpClient, user_identifier: str) -> Optional[Dict[str, Any]]:
    """Find user by ID, login, or email using OktaMcpClient."""
    
    # Try direct lookup by ID first if it looks like an Okta ID
    if user_identifier.startswith("00u"):
        try:
            raw_response = await okta_client.client.get_user(user_identifier)
            user, resp, err = normalize_okta_response(raw_response)
            if not err and user:
                return user.to_dict() if hasattr(user, 'to_dict') else user
        except Exception:
            pass
    
    # Try filter-based search (more precise than query search)
    try:
        if "@" in user_identifier:
            # Search by email filter
            raw_response = await okta_client.client.list_users({"filter": f'profile.email eq "{user_identifier}"'})
        else:
            # Search by login filter
            raw_response = await okta_client.client.list_users({"filter": f'profile.login eq "{user_identifier}"'})
        
        users, resp, err = normalize_okta_response(raw_response)
        if not err and users:
            first_user = users[0]
            return first_user.to_dict() if hasattr(first_user, 'to_dict') else first_user
            
    except Exception:
        pass
    
    # Fallback to query parameter search
    try:
        raw_response = await okta_client.client.list_users({"q": user_identifier})
        users, resp, err = normalize_okta_response(raw_response)
        
        if not err and users:
            # Look for exact match on email or login
            for user in users:
                user_dict = user.to_dict() if hasattr(user, 'to_dict') else user
                profile = user_dict.get("profile", {})
                if (profile.get("email", "").lower() == user_identifier.lower() or
                    profile.get("login", "").lower() == user_identifier.lower()):
                    return user_dict
            
            # Return first match if no exact match
            first_user = users[0]
            return first_user.to_dict() if hasattr(first_user, 'to_dict') else first_user
            
    except Exception:
        pass
    
    return None


async def find_group(okta_client: OktaMcpClient, group_identifier: str) -> Optional[Dict[str, Any]]:
    """Find group by ID or name using OktaMcpClient."""
    
    # Try direct lookup by ID first if it looks like an Okta ID
    if group_identifier.startswith("00g"):
        try:
            raw_response = await okta_client.client.get_group(group_identifier)
            group, resp, err = normalize_okta_response(raw_response)
            if not err and group:
                return group.to_dict() if hasattr(group, 'to_dict') else group
        except Exception:
            pass
    
    # Search by query parameter
    try:
        raw_response = await okta_client.client.list_groups({"q": group_identifier})
        groups, resp, err = normalize_okta_response(raw_response)
        
        if not err and groups:
            # Look for exact match on group name
            for group in groups:
                group_dict = group.to_dict() if hasattr(group, 'to_dict') else group
                profile = group_dict.get("profile", {})
                if profile.get("name", "").lower() == group_identifier.lower():
                    return group_dict
            
            # Return first match if no exact match
            first_group = groups[0]
            return first_group.to_dict() if hasattr(first_group, 'to_dict') else first_group
            
    except Exception:
        pass
    
    return None


async def check_user_app_assignment(okta_client: OktaMcpClient, app_id: str, user_id: str) -> Dict[str, Any]:
    """Check if user is assigned to application and collect comprehensive assignment data."""
    
    assignment_result = {
        "is_assigned": False,
        "assignment_type": "none",
        "direct_assignment": False
    }
    
    # Check direct assignment
    try:
        raw_response = await okta_client.client.get_application_user(app_id, user_id)
        user_assignment, resp, err = normalize_okta_response(raw_response)
        
        if not err and user_assignment:
            assignment_result.update({
                "is_assigned": True,
                "assignment_type": "direct",
                "direct_assignment": True
            })
            return assignment_result
            
    except Exception:
        pass
    
    # If direct assignment fails, check through groups
    try:
        # Get user's groups
        raw_response = await okta_client.client.list_user_groups(user_id)
        user_groups_data, resp, err = normalize_okta_response(raw_response)
        
        if not err and user_groups_data:
            user_groups = []
            user_group_ids = []
            
            for group in user_groups_data:
                group_dict = group.to_dict() if hasattr(group, 'to_dict') else group
                user_groups.append({
                    "id": group_dict.get("id"),
                    "name": group_dict.get("profile", {}).get("name")
                })
                user_group_ids.append(group_dict.get("id"))
            
            assignment_result["user_groups"] = user_groups
            
            # Check if any of these groups are assigned to the app
            raw_response = await okta_client.client.list_application_group_assignments(app_id)
            app_groups_data, resp, err = normalize_okta_response(raw_response)
            
            if not err and app_groups_data:
                app_group_ids = set()
                for group in app_groups_data:
                    group_dict = group.to_dict() if hasattr(group, 'to_dict') else group
                    app_group_ids.add(group_dict.get("id"))
                
                group_assignments = []
                for user_group in user_groups:
                    if user_group["id"] in app_group_ids:
                        group_assignments.append(user_group)
                
                if group_assignments:
                    assignment_result.update({
                        "is_assigned": True,
                        "assignment_type": "group",
                        "direct_assignment": False,
                        "via_groups": group_assignments,
                        "assigned_via_group": group_assignments[0]["name"]  # For backward compatibility
                    })
                else:
                    assignment_result["via_groups"] = []
                    
    except Exception:
        pass
    
    return assignment_result


async def check_group_app_assignment(okta_client: OktaMcpClient, app_id: str, group_id: str) -> Dict[str, Any]:
    """Check if group is assigned to application."""
    
    assignment_result = {
        "is_assigned": False,
        "assignment_type": "none",
        "group_assignment": False
    }
    
    try:
        # Check if group is assigned to application
        raw_response = await okta_client.client.list_application_group_assignments(app_id)
        app_groups_data, resp, err = normalize_okta_response(raw_response)
        
        if not err and app_groups_data:
            for app_group in app_groups_data:
                app_group_dict = app_group.to_dict() if hasattr(app_group, 'to_dict') else app_group
                if app_group_dict.get("id") == group_id:
                    assignment_result.update({
                        "is_assigned": True,
                        "assignment_type": "group",
                        "group_assignment": True
                    })
                    break
                    
    except Exception:
        pass
    
    return assignment_result