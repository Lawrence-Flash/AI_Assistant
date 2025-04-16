/**
 * Voice recognition and speech synthesis functionality
 */
class VoiceAssistant {
    constructor() {
        this.recognition = null;
        this.isListening = false;
        this.speechSynthesis = window.speechSynthesis;
        this.initializeVoiceRecognition();
    }

    initializeVoiceRecognition() {
        if (!('webkitSpeechRecognition' in window) && !('SpeechRecognition' in window)) {
            console.error("Speech recognition not supported in this browser");
            return;
        }

        // Create speech recognition object
        const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
        this.recognition = new SpeechRecognition();
        this.recognition.continuous = false;
        this.recognition.interimResults = false;
        this.recognition.lang = 'en-US';

        // Set up event handlers
        this.recognition.onstart = () => {
            this.isListening = true;
            document.getElementById('voice-status').textContent = 'Listening...';
            document.getElementById('mic-button').classList.add('listening');
        };

        this.recognition.onend = () => {
            this.isListening = false;
            document.getElementById('voice-status').textContent = 'Microphone off';
            document.getElementById('mic-button').classList.remove('listening');
        };

        this.recognition.onerror = (event) => {
            console.error('Speech recognition error:', event.error);
            document.getElementById('voice-status').textContent = `Error: ${event.error}`;
            this.isListening = false;
            document.getElementById('mic-button').classList.remove('listening');
        };

        this.recognition.onresult = (event) => {
            const lastResult = event.results[event.results.length - 1];
            const transcript = lastResult[0].transcript.trim();
            document.getElementById('voice-status').textContent = `You said: ${transcript}`;
            
            // Process the voice command
            this.processVoiceCommand(transcript);
        };
    }

    startListening() {
        if (!this.recognition) {
            this.speak("Voice recognition is not supported in this browser.");
            return;
        }

        if (!this.isListening) {
            try {
                this.recognition.start();
            } catch (error) {
                console.error("Error starting speech recognition:", error);
                document.getElementById('voice-status').textContent = "Error starting recognition";
            }
        }
    }

    stopListening() {
        if (this.recognition && this.isListening) {
            this.recognition.stop();
        }
    }

    speak(text) {
        // Cancel any ongoing speech
        this.speechSynthesis.cancel();

        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 1.0;
        utterance.pitch = 1.0;
        utterance.volume = 1.0;

        // Get available voices and select a good one if available
        let voices = this.speechSynthesis.getVoices();
        if (voices.length > 0) {
            // Try to find a good English voice
            const englishVoice = voices.find(voice => 
                (voice.lang.includes('en-US') || voice.lang.includes('en-GB')) && 
                !voice.name.includes('Microsoft')
            );
            
            if (englishVoice) {
                utterance.voice = englishVoice;
            }
        }

        this.speechSynthesis.speak(utterance);
    }

    processVoiceCommand(command) {
        const lowerCommand = command.toLowerCase();

        // Handle "scan" or "scan network" commands
        if (lowerCommand.includes('scan') || lowerCommand.includes('scan network')) {
            // Check if the command also includes a target
            const targetMatch = lowerCommand.match(/scan\s+(network\s+)?(for\s+)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(?:[0-9]{1,3}\.){3}[0-9]{1,3})/i);
            
            if (targetMatch && targetMatch[3]) {
                const target = targetMatch[3];
                document.getElementById('target-input').value = target;
                this.speak(`Scanning ${target}`);
                document.getElementById('scan-form').dispatchEvent(new Event('submit'));
            } else {
                this.speak("Please provide a target to scan. You can say 'scan' followed by an IP address or domain name.");
            }
            return;
        }

        // Handle "show history" command
        if (lowerCommand.includes('history') || lowerCommand.includes('show history')) {
            this.speak("Showing scan history");
            window.location.href = '/history';
            return;
        }

        // Handle "go home" or "go back" commands
        if (lowerCommand.includes('home') || lowerCommand.includes('go back') || lowerCommand.includes('main page')) {
            this.speak("Going to home page");
            window.location.href = '/';
            return;
        }

        // Handle "help" command
        if (lowerCommand.includes('help') || lowerCommand.includes('what can you do')) {
            this.speak("I can help with network scanning. Try saying 'scan' followed by a domain or IP address, or 'show history' to view past scans.");
            return;
        }

        // Default response for unrecognized commands
        this.speak("I didn't understand that command. Try saying 'scan' followed by a domain or IP address, or say 'help' for assistance.");
    }
}

// Export for use in other scripts
window.VoiceAssistant = VoiceAssistant;
