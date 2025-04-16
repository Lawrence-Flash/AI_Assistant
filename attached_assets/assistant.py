import speech_recognition as sr
import pyttsx3
import subprocess
import shutil
import re

#initialization of a global objects for efficiency
engine = pyttsx3.init()
recognizer= sr.Recognizer()

#Global variable to track input mode (voice or text)
input_mode = "voice"

def speak(text):
    """ this function converts text to speech"""
    engine.say(text)
    engine.runAndWait()

def listen(max_attempts=3):
    """Handles both voice and text input based on user preferences"""
    if input_mode == "text":
        command = input("Enter your command: ")
        print(f"You entered: {command}")
        return command

    # voice input mode
    attempts = 0
    while attempts < max_attempts:
        with sr.Microphone() as source:
            print("Listening...")
            recognizer.adjust_for_ambient_noise(source)
            audio = recognizer.listen(source)
        try:
            command = recognizer.recognize_google(audio)
            print(f"You said: {command}")
            return command
        except sr.UnknownValueError:
            print("Sorry, I couldn't unserstand.")
            attempts += 1
        except sr.RequestError:
            print("Could not connect to speech recognition service.")
            return None
    speak("Too many failed attempts: Please try typing your command.")
    command = input("Enter your command: ")
    print(f"You entered: {command}")
    return command

def is_valid_target(target):
    """Validates IP or Domain"""
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    domain_pattern = r"[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$"
    return re.match(ip_pattern, target) or re.match(domain_pattern, target)

def check_nmap():
    #check if Nmap is installed
    return shutil.which("nmap") is not None

def run_nmap_scan(target):
    """Runs an Nmap Scan on the target"""
    if not check_nmap():
        speak("Nmap is not installed or not found in your system PATH.")
        print("Error: Nmap not found")
        return
    if not is_valid_target(target):
        speak("Invalid target. Please provide a valid IP or Domain. ")
        return
    try:
        speak(f"Scanning {target} with Nmap...")
        result = subprocess.run(["nmap", "-F", target], capture_output=True, text=True)
        print(result.stdout)
        speak("Scan complete. chack the terminal for results.")
    except subprocess.CalledProcessError as e:
        speak("Nmap scan failed")
        print("Nmap Error: ", e)
    except Exception as e:
        speak("An error occurred while scanning")
        print("Error: ", e)

def set_input_mode():
    """Prompts the user to choose input mode (voice or text)"""
    global input_mode
    speak("Would you like use voice or text input? say 'voice' or 'text'")
    print("Would you like use voice or text input? say 'voice' or 'text'")
    choice = listen()
    if choice:
        choice = choice.lower()
        if "voice" in choice:
            input_mode = "voice"
            speak("Voice input selected")
        elif "text" in choice:
            input_mode = "text"
            speak("Text input selected")
        else:
            input_mode = "text" # Default to text if choice is unclear
            speak("I didn't understand your choice. Defaulting to text input")


def main():
    speak("Hello! i am your AI cybersecurity Assistant")
    print("Hello! i am your AI Cybersecurity Assistant")
    speak("Please choose your input mode")
    print("Please choose your command input mode")
    set_input_mode()
    speak("How can i help you today?")
    print("How can help you today?")
    while True:
        command = listen()
        if command:
            command = command.lower()
            if "scan network" in command:
                speak("Please provide the target IP or domain.")
                target = listen()
                if target:
                    run_nmap_scan(target)
            elif "exit" in command or "stop" in command:
                speak("Goodbye")
                break
            else:
                speak("Sorry, i couldn't recognize that command. Try saying 'scan network' or 'exit'")


if __name__ == "__main__":
    main()

