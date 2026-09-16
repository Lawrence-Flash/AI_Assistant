package com.example.aiassistant

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.BorderStroke
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.aiassistant.api.*
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            TerminalTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainScreen()
                }
            }
        }
    }
}

@Composable
fun TerminalTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = MaterialTheme.colorScheme.copy(
            background = Color.Black,
            onBackground = Color.Green,
            primary = Color.Green
        ),
        content = content
    )
}

enum class Screen {
    Terminal, Dashboard
}

@Composable
fun MainScreen() {
    var currentScreen by remember { mutableStateOf(Screen.Terminal) }
    var latestScanResult by remember { mutableStateOf<ScanResponse?>(null) }
    var latestHistory by remember { mutableStateOf<List<HistoryItem>>(emptyList()) }

    Scaffold(
        bottomBar = {
            NavigationBar(
                containerColor = Color(0xFF111111),
                contentColor = Color.Green
            ) {
                NavigationBarItem(
                    icon = { Icon(Icons.Filled.Code, contentDescription = "Terminal") },
                    label = { Text("Terminal", fontFamily = FontFamily.Monospace) },
                    selected = currentScreen == Screen.Terminal,
                    onClick = { currentScreen = Screen.Terminal },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = Color.Black,
                        selectedTextColor = Color.Green,
                        indicatorColor = Color.Green,
                        unselectedIconColor = Color.Gray,
                        unselectedTextColor = Color.Gray
                    )
                )
                NavigationBarItem(
                    icon = { Icon(Icons.Filled.Dashboard, contentDescription = "Dashboard") },
                    label = { Text("Dashboard", fontFamily = FontFamily.Monospace) },
                    selected = currentScreen == Screen.Dashboard,
                    onClick = { currentScreen = Screen.Dashboard },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = Color.Black,
                        selectedTextColor = Color.Green,
                        indicatorColor = Color.Green,
                        unselectedIconColor = Color.Gray,
                        unselectedTextColor = Color.Gray
                    )
                )
            }
        }
    ) { paddingValues ->
        Box(modifier = Modifier.padding(paddingValues)) {
            when (currentScreen) {
                Screen.Terminal -> TerminalScreen(
                    onScanComplete = { result -> latestScanResult = result },
                    onHistoryLoaded = { history -> latestHistory = history }
                )
                Screen.Dashboard -> DashboardScreen(
                    latestScan = latestScanResult,
                    history = latestHistory
                )
            }
        }
    }
}

@Composable
fun DashboardScreen(latestScan: ScanResponse?, history: List<HistoryItem>) {
    val coroutineScope = rememberCoroutineScope()
    var remediationScript by remember(latestScan) { mutableStateOf<String?>(null) }
    var isGeneratingScript by remember(latestScan) { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0A0A0A))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Text(
                "SECURITY DASHBOARD",
                color = Color.Green,
                fontSize = 24.sp,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold
            )
            Divider(color = Color.Green, thickness = 2.dp, modifier = Modifier.padding(vertical = 8.dp))
        }

        if (latestScan != null) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF1A1A1A)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Latest Scan Target: ${latestScan.target}", color = Color.White, fontFamily = FontFamily.Monospace)
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        val riskColor = when (latestScan.risk_level.uppercase()) {
                            "CRITICAL", "HIGH" -> Color.Red
                            "MEDIUM" -> Color.Yellow
                            else -> Color.Green
                        }
                        Text("Risk Level: ${latestScan.risk_level}", color = riskColor, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        Text("AI Analysis Summary:", color = Color.Gray, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                        Text(
                            text = latestScan.ai_analysis.take(300) + "...",
                            color = Color.LightGray,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp
                        )
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        // Remediation Script Generator
                        if (isGeneratingScript) {
                            CircularProgressIndicator(color = Color.Green, modifier = Modifier.size(24.dp))
                        } else if (remediationScript == null) {
                            OutlinedButton(
                                onClick = {
                                    isGeneratingScript = true
                                    coroutineScope.launch {
                                        try {
                                            val request = RemediationRequest(
                                                target = latestScan.target,
                                                scan_summary = latestScan.ai_analysis
                                            )
                                            val response = ApiClient.instance.getRemediation(request)
                                            if (response.success) {
                                                remediationScript = response.script
                                            } else {
                                                remediationScript = "Error: Could not generate script."
                                            }
                                        } catch (e: Exception) {
                                            remediationScript = "Failed to fetch script: ${e.message}"
                                        } finally {
                                            isGeneratingScript = false
                                        }
                                    }
                                },
                                border = BorderStroke(1.dp, Color.Green)
                            ) {
                                Text("Generate Bash Hardening Script", color = Color.Green, fontFamily = FontFamily.Monospace)
                            }
                        } else {
                            Text("Hardening Script (Bash):", color = Color.Green, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                            Spacer(modifier = Modifier.height(4.dp))
                            SelectionContainer {
                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(Color.Black)
                                        .padding(8.dp)
                                ) {
                                    Text(
                                        text = remediationScript ?: "",
                                        color = Color.LightGray,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 10.sp
                                    )
                                }
                            }
                        }
                    }
                }
            }
        } else {
            item {
                Text("No recent scans. Run a scan in the terminal.", color = Color.Gray, fontFamily = FontFamily.Monospace)
            }
        }

        item {
            Spacer(modifier = Modifier.height(16.dp))
            Text("Recent History", color = Color.Green, fontSize = 18.sp, fontFamily = FontFamily.Monospace)
        }

        if (history.isNotEmpty()) {
            items(history.take(5)) { item ->
                val riskColor = when (item.risk_level.uppercase()) {
                    "CRITICAL", "HIGH" -> Color.Red
                    "MEDIUM" -> Color.Yellow
                    else -> Color.Green
                }
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(item.target, color = Color.White, fontFamily = FontFamily.Monospace)
                    Text(item.risk_level, color = riskColor, fontFamily = FontFamily.Monospace)
                }
                Divider(color = Color.DarkGray)
            }
        } else {
            item {
                Text("Run 'history' in terminal to load data.", color = Color.Gray, fontFamily = FontFamily.Monospace)
            }
        }
    }
}

data class TerminalLine(val text: String, val isCommand: Boolean = false)

@Composable
fun TerminalScreen(
    onScanComplete: (ScanResponse) -> Unit,
    onHistoryLoaded: (List<HistoryItem>) -> Unit
) {
    val coroutineScope = rememberCoroutineScope()
    var lines by remember { mutableStateOf(listOf(
        TerminalLine("AI-Cybersecurity Assistant v2.5 (Terminal Mode) initialized.", false),
        TerminalLine("Type 'help' for available commands.", false)
    )) }
    
    // Command History State
    var commandHistory by remember { mutableStateOf(listOf<String>()) }
    var historyIndex by remember { mutableStateOf(-1) }
    
    var input by remember { mutableStateOf("") }
    val listState = rememberLazyListState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black)
            .padding(16.dp)
    ) {
        LazyColumn(
            modifier = Modifier.weight(1f),
            state = listState,
            verticalArrangement = Arrangement.Bottom
        ) {
            items(lines) { line ->
                val textColor = if (line.isCommand) Color.White else Color.Green
                val prefix = if (line.isCommand) "user@ai-assistant:~$ " else ""
                Text(
                    text = "$prefix${line.text}",
                    color = textColor,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 14.sp
                )
            }
        }
        
        LaunchedEffect(lines.size) {
            if (lines.isNotEmpty()) {
                listState.animateScrollToItem(lines.size - 1)
            }
        }

        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(top = 8.dp)
        ) {
            Text(
                text = "user@ai-assistant:~$ ",
                color = Color.Green,
                fontFamily = FontFamily.Monospace,
                fontSize = 14.sp
            )
            BasicTextField(
                value = input,
                onValueChange = { newValue -> 
                    // Reset history index if user starts typing manually
                    if (newValue != input && historyIndex != -1) {
                        historyIndex = -1
                    }
                    input = newValue 
                },
                textStyle = TextStyle(
                    color = Color.Green,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 14.sp
                ),
                cursorBrush = SolidColor(Color.Green),
                modifier = Modifier.weight(1f),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Go),
                keyboardActions = KeyboardActions(
                    onGo = {
                        if (input.isNotBlank()) {
                            val command = input.trim()
                            lines = lines + TerminalLine(command, true)
                            
                            // Add to history
                            commandHistory = commandHistory + command
                            historyIndex = -1
                            
                            input = ""
                            
                            if (command.lowercase() == "clear") {
                                lines = emptyList()
                            } else {
                                // Process command
                                coroutineScope.launch {
                                    processCommand(command, { newLine ->
                                        lines = lines + TerminalLine(newLine, false)
                                    }, onScanComplete, onHistoryLoaded)
                                }
                            }
                        }
                    }
                )
            )
            
            // Minimal Up/Down arrows for command history since hardware keyboards are rare on phones
            Row(modifier = Modifier.padding(start = 8.dp)) {
                IconButton(
                    onClick = {
                        if (commandHistory.isNotEmpty()) {
                            if (historyIndex == -1) {
                                historyIndex = commandHistory.size - 1
                            } else if (historyIndex > 0) {
                                historyIndex--
                            }
                            input = commandHistory[historyIndex]
                        }
                    },
                    modifier = Modifier.size(24.dp)
                ) {
                    Text("↑", color = Color.Green, fontSize = 20.sp, fontFamily = FontFamily.Monospace)
                }
                IconButton(
                    onClick = {
                        if (commandHistory.isNotEmpty() && historyIndex != -1) {
                            if (historyIndex < commandHistory.size - 1) {
                                historyIndex++
                                input = commandHistory[historyIndex]
                            } else {
                                historyIndex = -1
                                input = ""
                            }
                        }
                    },
                    modifier = Modifier.size(24.dp)
                ) {
                    Text("↓", color = Color.Green, fontSize = 20.sp, fontFamily = FontFamily.Monospace)
                }
            }
        }
    }
}

suspend fun processCommand(
    command: String, 
    onOutput: (String) -> Unit,
    onScanComplete: (ScanResponse) -> Unit,
    onHistoryLoaded: (List<HistoryItem>) -> Unit
) {
    // Regex to split by spaces, but keep quoted strings together
    val regex = Regex("\"([^\"]*)\"|'([^']*)'|([^\\s]+)")
    val argsList = regex.findAll(command).map { 
        it.groupValues[1].ifEmpty { it.groupValues[2].ifEmpty { it.groupValues[3] } } 
    }.toList()

    if (argsList.isEmpty()) return

    val cmd = argsList[0].lowercase()
    val argsString = command.removePrefix(argsList[0]).trim()

    try {
        when (cmd) {
            "help" -> {
                onOutput("Available commands:")
                onOutput("  scan <target> [-p <ports>] [-t <type>] - Run an Nmap scan")
                onOutput("     Types: fast, advanced, web, stealth, vuln, full")
                onOutput("  subdomains <target> - Map subdomains")
                onOutput("  dns <target>      - Fetch DNS, WHOIS, and Email Security records")
                onOutput("  searchcve <keyword> - Query the National Vulnerability Database")
                onOutput("  audit \"<text>\"  - Audit local config (e.g. LinPEAS snippet) for misconfigs")
                onOutput("  history           - View recent scan history")
                onOutput("  chat <message>    - Chat with the AI advisor")
                onOutput("  clear             - Clear the terminal screen")
            }
            "audit" -> {
                if (argsString.isEmpty()) {
                    onOutput("Error: Missing text. Usage: audit \"<system output snippet>\"")
                    return
                }
                onOutput("Auditing local configuration...")
                try {
                    val response = ApiClient.instance.auditConfig(AuditRequest(config_text = argsString))
                    if (response.success && response.analysis != null) {
                        onOutput("\n--- AI AUDIT RESULT ---")
                        onOutput(response.analysis)
                    } else {
                        onOutput("Audit failed: ${response.error ?: "Unknown error"}")
                    }
                } catch(e: Exception) {
                     onOutput("Failed to connect to backend: ${e.message}")
                }
            }
            "searchcve", "cve" -> {
                if (argsList.size < 2) {
                    onOutput("Error: Missing keyword. Usage: searchcve <service name>")
                    return
                }
                val keyword = argsString
                onOutput("Querying Vulnerability Database for '$keyword'...")
                try {
                    val response = ApiClient.instance.searchCve(CveSearchRequest(keyword = keyword))
                    if (response.success && response.cves != null) {
                        if (response.cves.isEmpty()) {
                            onOutput("No known vulnerabilities found for '$keyword'.")
                        } else {
                            onOutput("Top CVEs found:")
                            response.cves.forEach { cve ->
                                val severityColor = when {
                                    (cve.cvss?.toFloatOrNull() ?: 0f) >= 9.0 -> "🔴" // Critical
                                    (cve.cvss?.toFloatOrNull() ?: 0f) >= 7.0 -> "🟠" // High
                                    (cve.cvss?.toFloatOrNull() ?: 0f) >= 4.0 -> "🟡" // Medium
                                    else -> "🟢" // Low
                                }
                                onOutput("[$severityColor ${cve.cvss ?: "N/A"}] ${cve.id}")
                                onOutput("   └ ${cve.summary.take(120)}...")
                            }
                        }
                    } else {
                        onOutput("CVE Search failed: ${response.error ?: "Unknown error"}")
                    }
                } catch(e: Exception) {
                     onOutput("Failed to connect to backend: ${e.message}")
                }
            }
            "dns", "whois" -> {
                if (argsList.size < 2) {
                    onOutput("Error: Missing target. Usage: dns <target>")
                    return
                }
                val target = argsList[1]
                onOutput("Running OSINT / DNS audit on $target...")
                try {
                    val response = ApiClient.instance.domainAudit(DomainAuditRequest(domain = target))
                    if (response.success && response.data != null) {
                        val dnsData = response.data["dns"] as? Map<*, *>
                        val whoisData = response.data["whois"] as? Map<*, *>
                        val emailSec = response.data["email_security"] as? Map<*, *>
                        
                        onOutput("\n--- WHOIS INFO ---")
                        if (whoisData != null) {
                            onOutput("Registrar: ${whoisData["registrar"]}")
                            onOutput("Created: ${whoisData["creation_date"]}")
                            onOutput("Expires: ${whoisData["expiration_date"]}")
                        } else {
                            onOutput("No WHOIS data found.")
                        }
                        
                        onOutput("\n--- DNS RECORDS ---")
                        if (dnsData != null) {
                            (dnsData["A"] as? List<*>)?.let { if (it.isNotEmpty()) onOutput("A: $it") }
                            (dnsData["MX"] as? List<*>)?.let { if (it.isNotEmpty()) onOutput("MX: $it") }
                            (dnsData["NS"] as? List<*>)?.let { if (it.isNotEmpty()) onOutput("NS: $it") }
                            (dnsData["TXT"] as? List<*>)?.let { if (it.isNotEmpty()) onOutput("TXT (First 2): ${it.take(2)}") }
                        } else {
                            onOutput("No DNS records resolved.")
                        }

                        onOutput("\n--- EMAIL SPOOFING DEFENSE ---")
                        if (emailSec != null) {
                            val protection = emailSec["protection_status"]
                            onOutput("Status: $protection")
                        }
                    } else {
                        onOutput("Audit failed: ${response.error ?: "Unknown error"}")
                    }
                } catch(e: Exception) {
                     onOutput("Failed to connect to backend: ${e.message}")
                }
            }
            "scan" -> {
                if (argsList.size < 2) {
                    onOutput("Error: Missing target. Usage: scan <target> [-p <ports>]")
                    return
                }
                
                val target = argsList[1]
                var customPorts: String? = null
                var scanType = "fast"
                
                // Very basic flag parsing
                var i = 2
                while (i < argsList.size) {
                    when (argsList[i]) {
                        "-p", "--ports" -> {
                            if (i + 1 < argsList.size) {
                                customPorts = argsList[i + 1]
                                i++
                            }
                        }
                        "-t", "--type" -> {
                            if (i + 1 < argsList.size) {
                                scanType = argsList[i + 1]
                                i++
                            }
                        }
                    }
                    i++
                }

                onOutput("Initiating '$scanType' scan on $target" + (customPorts?.let { " (Ports: $it)" } ?: "") + "...")
                try {
                     val request = ScanRequest(
                         target = target, 
                         scan_type = scanType, 
                         custom_ports = customPorts
                     )
                     val response = ApiClient.instance.startScan(request)
                     onOutput("Scan Complete: [Risk Level: ${response.risk_level}]")
                     
                     onScanComplete(response) // Pass to Dashboard
                     
                     // Limit analysis output to keep the terminal from freezing
                     val analysisPreview = response.ai_analysis.take(200).replace("\n", " ") + "..."
                     onOutput("AI Analysis: $analysisPreview")
                } catch (e: Exception) {
                     onOutput("Failed to connect to backend: ${e.message}")
                     onOutput("Tip: Ensure your backend is running and the Emulator IP (10.0.2.2) can reach it.")
                }
            }
            "subdomains" -> {
                if (argsList.size < 2) {
                    onOutput("Error: Missing domain. Usage: subdomains <domain>")
                    return
                }
                val target = argsList[1]
                onOutput("Mapping subdomains for $target...")
                try {
                    val response = ApiClient.instance.subdomains(SubdomainRequest(domain = target))
                    onOutput("Found ${response.subdomains.size} subdomains:")
                    response.subdomains.forEach { sub ->
                        val ip = sub.ip ?: "Unknown IP"
                        onOutput("  - ${sub.subdomain} ($ip)")
                    }
                } catch(e: Exception) {
                     onOutput("Failed to connect to backend: ${e.message}")
                }
            }
             "chat" -> {
                if (argsString.isEmpty()) {
                    onOutput("Error: Missing message. Usage: chat <message>")
                } else {
                    onOutput("AI is thinking...")
                    try {
                         val response = ApiClient.instance.chat(ChatRequest(message = argsString))
                         onOutput("AI: ${response.reply}")
                    } catch (e: Exception) {
                         onOutput("Failed to connect to backend: ${e.message}")
                    }
                }
            }
            "history" -> {
                 try {
                     onOutput("Fetching history...")
                     val response = ApiClient.instance.getHistory()
                     if (response.isEmpty()) {
                         onOutput("History is empty.")
                     } else {
                         onHistoryLoaded(response) // Pass to Dashboard
                         response.forEach { item ->
                             onOutput("[${item.id}] ${item.target} - Risk: ${item.risk_level} (${item.timestamp})")
                         }
                     }
                 } catch (e: Exception) {
                     onOutput("Failed to connect to backend: ${e.message}")
                 }
            }
            "clear" -> {
                 // Handled in the UI layer now
            }
            else -> {
                onOutput("bash: $cmd: command not found")
            }
        }
    } catch (e: Exception) {
        onOutput("Error executing command: ${e.message}")
    }
}

@Preview(showBackground = true)
@Composable
fun TerminalPreview() {
    TerminalTheme {
        TerminalScreen(onScanComplete = {}, onHistoryLoaded = {})
    }
}