# LLM Provider OAuth Authentication Support Research

## Executive Summary

This document provides a comprehensive overview of OAuth authentication support across major LLM providers and AI platforms. Most providers use API key-based authentication, with enterprise-focused OAuth/OIDC support primarily available through cloud platforms (Azure, AWS, GCP) rather than direct API access.

---

## Major LLM Providers

### 1. OpenAI
- **OAuth Support:** No (for API access)
- **OAuth Type:** N/A
- **Documentation:** https://platform.openai.com/docs/api-reference/authentication
- **Notes:** 
  - OpenAI uses API key-based authentication only (`Authorization: Bearer sk-...`)
  - No native OAuth 2.0 or OIDC support for API access
  - Enterprise SSO available for OpenAI ChatGPT Enterprise (web interface), not API

---

### 2. Anthropic (Claude)
- **OAuth Support:** No (for API access)
- **OAuth Type:** N/A
- **Documentation:** https://docs.anthropic.com/en/api/getting-started
- **Notes:**
  - API key authentication only (`x-api-key: ...`)
  - No OAuth 2.0 or OIDC support for API access
  - Enterprise features available through direct partnerships

---

### 3. Google (Gemini API)
- **OAuth Support:** Yes
- **OAuth Type:** OAuth 2.0
- **Documentation:** https://ai.google.dev/gemini-api/docs/oauth
- **Notes:**
  - Supports OAuth 2.0 for user authentication flows
  - Also supports API keys for server-to-server scenarios
  - OAuth recommended for client-side applications
  - Requires Google Cloud project setup
  - Supports service account authentication for backend services

---

### 4. Mistral AI
- **OAuth Support:** No
- **OAuth Type:** N/A
- **Documentation:** https://docs.mistral.ai/
- **Notes:**
  - API key authentication only
  - No OAuth support documented

---

### 5. Cohere
- **OAuth Support:** No
- **OAuth Type:** N/A
- **Documentation:** https://docs.cohere.com/docs/authentication
- **Notes:**
  - API key authentication only
  - No OAuth support documented

---

### 6. AI21 Labs
- **OAuth Support:** No
- **OAuth Type:** N/A
- **Documentation:** https://docs.ai21.com/
- **Notes:**
  - API key authentication only
  - No OAuth support documented

---

## Cloud Platforms (Enterprise OAuth/SSO)

### 7. Azure OpenAI Service
- **OAuth Support:** Yes
- **OAuth Type:** OAuth 2.0, OIDC, Azure AD/Entra ID
- **Documentation:** https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/managed-identity
- **Notes:**
  - Full Azure Active Directory (now Microsoft Entra ID) integration
  - Supports managed identities for Azure resources
  - OAuth 2.0 client credentials flow supported
  - Enterprise SSO through Azure AD
  - Role-based access control (RBAC) available
  - Conditional Access policies supported

---

### 8. AWS Bedrock
- **OAuth Support:** Partial (via IAM Identity Center / SSO)
- **OAuth Type:** OIDC, SAML 2.0 (for console access)
- **Documentation:** https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam.html
- **Notes:**
  - API access uses AWS Signature Version 4 (not OAuth)
  - AWS IAM Identity Center supports OIDC/SAML for console access
  - Identity federation supported through IAM
  - Cross-account access via IAM roles
  - No native OAuth for API calls - uses AWS credentials

---

### 9. Google Cloud Vertex AI
- **OAuth Support:** Yes
- **OAuth Type:** OAuth 2.0, OIDC
- **Documentation:** https://cloud.google.com/vertex-ai/docs/authentication
- **Notes:**
  - Full OAuth 2.0 support through Google Cloud IAM
  - Service account authentication
  - Workload Identity Federation (external identity providers)
  - Supports OIDC for identity federation
  - Application Default Credentials (ADC) for simplified auth

---

## Additional Providers

### 10. Meta (Llama)
- **OAuth Support:** No
- **OAuth Type:** N/A
- **Notes:**
  - Open source models - no centralized API
  - Authentication depends on hosting provider
  - If using through cloud providers (AWS, Azure), inherits their auth

### 11. Stability AI
- **OAuth Support:** No
- **OAuth Type:** N/A
- **Notes:**
  - API key authentication only

### 12. Perplexity
- **OAuth Support:** No
- **OAuth Type:** N/A
- **Notes:**
  - API key authentication only

---

## Summary Table

| Provider | OAuth Support | OAuth Type | Enterprise SSO |
|----------|---------------|------------|----------------|
| OpenAI | No | N/A | ChatGPT Enterprise only |
| Anthropic | No | N/A | Contact sales |
| Google Gemini | Yes | OAuth 2.0 | Via Google Cloud |
| Mistral | No | N/A | No |
| Cohere | No | N/A | No |
| AI21 | No | N/A | No |
| Azure OpenAI | Yes | OAuth 2.0, OIDC, Azure AD | Yes |
| AWS Bedrock | Partial | OIDC/SAML (console) | Via IAM Identity Center |
| GCP Vertex AI | Yes | OAuth 2.0, OIDC | Yes |

---

## Key Findings

1. **Direct API Access:** None of the major LLM providers (OpenAI, Anthropic, Mistral, Cohere, AI21) support OAuth for direct API authentication. They all use API keys.

2. **Enterprise OAuth:** OAuth/OIDC support is primarily available through cloud platforms (Azure, AWS, GCP) that host these models, not through the providers' direct APIs.

3. **Google Exception:** Google is the exception among direct providers, offering OAuth 2.0 for their Gemini API through Google Cloud.

4. **Best Practice:** For enterprise deployments requiring OAuth/SSO:
   - Use Azure OpenAI for Microsoft environments
   - Use GCP Vertex AI for Google environments
   - Use AWS Bedrock for AWS environments
   - Implement an API gateway/proxy with OAuth in front of direct provider APIs

---

## Implementation Recommendations

For BrainstormRouter or similar gateway services:

1. **For OAuth Support:** Integrate with cloud-hosted versions (Azure OpenAI, GCP Vertex AI) rather than direct APIs
2. **For Direct APIs:** Implement your own OAuth layer that proxies to API key-based services
3. **Hybrid Approach:** Support both OAuth (for enterprise) and API key (for individual developers) authentication patterns
