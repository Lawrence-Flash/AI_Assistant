package com.example.aiassistant.api

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST

data class ScanRequest(
    val target: String,
    val scan_type: String = "fast",
    val custom_ports: String? = null,
    val client_tag: String = "General",
    val analyst_notes: String = ""
)

data class ScanResponse(
    val success: Boolean,
    val scan_id: Int,
    val target: String,
    val client_tag: String,
    val analyst_notes: String,
    val nmap_result: String,
    // osint_result and ports can be complex objects, using Any? for now
    val osint_result: Any?,
    val ai_analysis: String,
    val ports: List<Any>?,
    val risk_level: String
)

data class HistoryItem(
    val id: Int,
    val target: String,
    val timestamp: String,
    val risk_level: String,
    val client_tag: String,
    val analyst_notes: String
)

data class ChatMessage(
    val role: String,
    val parts: List<String>
)

data class ChatRequest(
    val message: String,
    val history: List<ChatMessage> = emptyList(),
    val scan_context: String = ""
)

data class ChatResponse(
    val reply: String
)

data class SubdomainRequest(
    val domain: String
)

data class SubdomainResponse(
    val success: Boolean,
    val domain: String,
    val subdomains: List<SubdomainItem>
)

data class SubdomainItem(
    val subdomain: String,
    val ip: String?
)

data class DomainAuditRequest(
    val domain: String
)

data class DomainAuditResponse(
    val success: Boolean,
    val domain: String,
    val error: String?,
    val data: Map<String, Any>?
)

data class RemediationRequest(
    val target: String,
    val scan_summary: String,
    val platform: String = "linux"
)

data class RemediationResponse(
    val success: Boolean,
    val script: String,
    val platform: String
)

data class CveSearchRequest(
    val keyword: String
)

data class CveItem(
    val id: String,
    val cvss: String?,
    val summary: String
)

data class CveSearchResponse(
    val success: Boolean,
    val keyword: String,
    val error: String?,
    val cves: List<CveItem>?
)

data class AuditRequest(
    val config_text: String
)

data class AuditResponse(
    val success: Boolean,
    val analysis: String?,
    val error: String?
)

interface AiAssistantApi {
    @POST("scan")
    suspend fun startScan(@Body request: ScanRequest): ScanResponse

    @GET("history")
    suspend fun getHistory(): List<HistoryItem>
    
    @POST("chat")
    suspend fun chat(@Body request: ChatRequest): ChatResponse

    @POST("subdomains")
    suspend fun subdomains(@Body request: SubdomainRequest): SubdomainResponse

    @POST("domain_audit")
    suspend fun domainAudit(@Body request: DomainAuditRequest): DomainAuditResponse

    @POST("remediation")
    suspend fun getRemediation(@Body request: RemediationRequest): RemediationResponse

    @POST("search_cve")
    suspend fun searchCve(@Body request: CveSearchRequest): CveSearchResponse

    @POST("audit_config")
    suspend fun auditConfig(@Body request: AuditRequest): AuditResponse
}