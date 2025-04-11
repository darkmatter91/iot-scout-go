package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/c-bata/go-prompt"
	"github.com/fatih/color"
	"github.com/tarm/serial"
	"golang.org/x/term"
	"golang.org/x/text/encoding/charmap"
)

// Colors for terminal output
var (
	Cyan    = color.New(color.FgCyan, color.Bold).SprintFunc()
	Green   = color.New(color.FgGreen, color.Bold).SprintFunc()
	Blue    = color.New(color.FgBlue, color.Bold).SprintFunc()
	Red     = color.New(color.FgRed, color.Bold).SprintFunc()
	Yellow  = color.New(color.FgYellow, color.Bold).SprintFunc()
	Reset   = color.New(color.Reset).SprintFunc()
	Bold    = color.New(color.Bold).SprintFunc()
	White   = color.New(color.FgWhite, color.Bold).SprintFunc()
	Magenta = color.New(color.FgMagenta, color.Bold).SprintFunc()
)

// Initialize color output
func init() {
	color.NoColor = false
}

// Config holds application configuration
type Config struct {
	SerialPort   string
	BaudRate     int
	ByteSize     int
	Timeout      time.Duration
	BootWaitTime int
	CommandDelay int
	ReadDelay    int
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		SerialPort:   "/dev/ttyUSB0",
		BaudRate:     115200,
		ByteSize:     8,
		Timeout:      time.Second,
		BootWaitTime: 20,
		CommandDelay: 1,
		ReadDelay:    100,
	}
}

// CommandClassifier handles command classification and processing
type CommandClassifier struct {
	StandardCommands map[string]bool
	ServicesInfo     map[string]string
	VendorSpecific   map[string]bool
}

// NewCommandClassifier creates a new CommandClassifier
func NewCommandClassifier() *CommandClassifier {
	cc := &CommandClassifier{
		StandardCommands: make(map[string]bool),
		ServicesInfo:     make(map[string]string),
		VendorSpecific:   make(map[string]bool),
	}

	// Initialize standard commands
	standardCommands := []string{
		"ash", "sh", "bash", "cat", "chmod", "chown", "cp", "date", "dd", "df",
		"dmesg", "echo", "kill", "ln", "login", "ls", "mkdir", "mount", "mv",
		"pidof", "ping", "ping6", "ps", "pwd", "rm", "rmdir", "sed", "sleep",
		"sync", "umount", "uname", "nice", "renice", "ionice", "chroot",
		"stty", "true", "false", "yes", "printf", "env", "printenv",
		"busybox", "free", "top", "uptime", "killall", "reboot", "poweroff",
		"halt", "shutdown", "init", "sysctl", "klogd", "syslogd", "logger",
		"watchdog", "crond", "crontab", "at", "atd", "ntpd", "hwclock",
		"date", "time", "usleep", "sleep", "iostat", "mpstat", "vmstat",
		"pgrep", "pkill", "pwdx", "skill", "tload", "fuser", "lsof",
		"pmap", "pwck", "vlock", "chvt", "deallocvt", "dumpkmap", "loadkmap",
		"arp", "arping", "ifconfig", "ip", "route", "netstat", "ss",
		"nameif", "ipcalc", "netmsg", "traceroute", "tracepath", "ping",
		"ping6", "nslookup", "dig", "host", "hostname", "ifdown", "ifup",
		"ifenslave", "mii-tool", "ethtool", "tc", "ip6tables", "iptables",
		"dhcpd", "dhcpc", "dhclient", "udhcpc", "udhcpd", "radvd", "pppd",
		"pppoe", "wpa_supplicant", "hostapd", "dnsmasq", "ntpd", "ntpc",
		"ntpdate", "dropbear", "dropbearkey", "httpd", "inetd", "telnetd",
		"tftpd", "ftpd", "sshd", "smbd", "nmbd", "rpcbind", "portmap",
		"wget", "curl", "tftp", "ftp", "sftp", "scp", "rsync", "telnet",
		"ssh", "nc", "netcat", "socat", "tcpdump", "nmap", "mtr",
		"iperf", "iperf3", "speedtest", "iptraf", "nethogs", "iftop",
		"iwconfig", "iwlist", "iwpriv", "iwspy", "iwevent", "iw",
		"wpa_cli", "wpa_passphrase", "iwgetid", "rfkill", "wlanconfig",
		"wantype", "wandetect", "landetect", "bridgedetect", "vlanconfig",
		"switchconfig", "ethphxcmd", "mii_mgr", "flash", "mtd", "nvram",
		"fw_printenv", "fw_setenv", "ubootenv", "factorydefault", "firstboot",
		"led", "gpio", "i2c", "i2cdetect", "i2cdump", "i2cget", "i2cset",
		"touch", "find", "grep", "egrep", "fgrep", "gzip", "gunzip", "tar",
		"unzip", "vi", "vim", "nano", "head", "tail", "more", "less",
		"sort", "uniq", "wc", "which", "whereis", "locate", "xargs",
		"basename", "dirname", "realpath", "readlink", "md5sum", "sha1sum",
		"sha256sum", "sha512sum", "sum", "cksum", "cmp", "diff", "patch",
		"split", "csplit", "cut", "paste", "join", "tr", "expand", "unexpand",
		"fmt", "pr", "fold", "head", "tail", "nl", "od", "hexdump", "xxd",
		"strings", "file", "stat", "truncate", "shred", "tee",
		"passwd", "adduser", "deluser", "chpasswd", "useradd", "userdel",
		"groupadd", "groupdel", "sudo", "su", "chage", "last", "lastlog",
		"who", "w", "whoami", "groups", "id", "newgrp", "sg", "logname",
		"login", "sulogin", "vipw", "vigr",
		"fdisk", "sfdisk", "cfdisk", "parted", "mkfs", "mke2fs", "mkswap",
		"swapon", "swapoff", "fsck", "e2fsck", "tune2fs", "resize2fs",
		"dumpe2fs", "debugfs", "blkid", "findfs", "lsblk", "losetup",
		"mount", "umount", "mountpoint", "df", "du", "sync", "blockdev",
		"free", "slabtop", "vmstat", "pmap", "smem", "top", "htop",
		"lspci", "lsusb", "lsscsi", "dmidecode", "hdparm", "sdparm",
		"ethtool", "mii-tool", "setserial", "hwclock", "sensors",
		"iptables", "ip6tables", "arptables", "ebtables", "ipset",
		"fail2ban-client", "nft", "tcpd", "sudo", "su", "chroot",
		"ulimit", "chmod", "chown", "chgrp", "umask",
		"opkg", "ipkg", "dpkg", "rpm", "apt-get", "yum", "pacman",
		"strace", "ltrace", "gdb", "valgrind", "addr2line", "size",
		"nm", "objdump", "readelf", "ldd", "ldconfig",
	}

	for _, cmd := range standardCommands {
		cc.StandardCommands[cmd] = true
	}

	// Initialize services info
	cc.ServicesInfo = map[string]string{
		"init":          "Initial process",
		"dropbear":      "Lightweight SSH server",
		"httpd":         "HTTP server",
		"dhcpd":         "DHCP server",
		"wlNetlinkTool": "Wireless network tool",
		"wscd":          "Wi-Fi Simple Configuration daemon",
		"upnpd":         "UPnP daemon",
		"afcd":          "Apple Filing Protocol daemon",
		"dyndns":        "Dynamic DNS client",
		"noipdns":       "No-IP DNS client",
		"ntpc":          "NTP client",
		"tmpd":          "Temporary daemon",
		"dhcpc":         "DHCP client",
		"tdpd":          "Tunnel daemon",
		"cmxdns":        "Custom DNS client",
		"dhcp6s":        "DHCPv6 server",
		"cos":           "Custom operation service",
		"dnsProxy":      "DNS proxy",
		"igmpd":         "IGMP daemon",
	}

	// Initialize vendor-specific commands
	vendorSpecific := []string{
		"afcd", "ated_tp", "cmxdns", "cos", "dnsProxy", "dyndns", "ebtables",
		"igmpd", "ipping", "ipcrm", "ipcs", "iwpriv", "noipdns", "ntpc",
		"pwdog", "rt2860apd", "taskset", "tc", "tddp", "tdpd", "tmpd", "upnpd",
	}

	for _, cmd := range vendorSpecific {
		cc.VendorSpecific[cmd] = true
	}

	return cc
}

// GetBaseCmd extracts the base command from a command string
func (cc *CommandClassifier) GetBaseCmd(cmd string) string {
	if strings.HasPrefix(cmd, "[") && strings.HasSuffix(cmd, "]") {
		parts := strings.Split(cmd[1:len(cmd)-1], "/")
		return parts[0]
	}

	cmd = strings.TrimSpace(strings.TrimPrefix(cmd, "<"))
	parts := strings.Fields(cmd)
	if len(parts) > 0 {
		cmdParts := strings.Split(parts[0], "/")
		return cmdParts[len(cmdParts)-1]
	}

	return ""
}

// ClassifyCommand classifies a command and returns its description and color
func (cc *CommandClassifier) ClassifyCommand(cmd string, binCommands map[string]bool) (string, string) {
	if strings.HasPrefix(cmd, "[") && strings.HasSuffix(cmd, "]") {
		baseCmd := cc.GetBaseCmd(cmd)
		return fmt.Sprintf("Kernel thread: %s", baseCmd), Blue("")
	}

	baseCmd := cc.GetBaseCmd(cmd)
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(baseCmd) {
		return "Invalid command", Yellow("")
	}

	if cc.StandardCommands[baseCmd] {
		return fmt.Sprintf("Standard Linux Command: %s", baseCmd), Green("")
	} else {
		return fmt.Sprintf("Non-Standard (Vendor/Custom): %s", baseCmd), Red("")
	}
}

// SerialManager manages serial communication with the device
type SerialManager struct {
	Port       string
	BaudRate   int
	SerialPort *serial.Port
	Config     *Config
}

// NewSerialManager creates a new SerialManager
func NewSerialManager(port string) *SerialManager {
	config := &Config{
		SerialPort:   port,
		BaudRate:     115200,
		ByteSize:     8,
		Timeout:      time.Second,
		BootWaitTime: 20,
		CommandDelay: 1,
		ReadDelay:    100,
	}

	sm := &SerialManager{
		Port:     config.SerialPort,
		BaudRate: config.BaudRate,
		Config:   config,
	}

	return sm
}

// Connect establishes serial connection with error handling
func (sm *SerialManager) Connect() error {
	config := &serial.Config{
		Name:     sm.Port,
		Baud:     sm.BaudRate,
		Size:     byte(sm.Config.ByteSize),
		Parity:   serial.ParityNone,
		StopBits: serial.Stop1,
	}

	var err error
	sm.SerialPort, err = serial.OpenPort(config)
	if err != nil {
		return fmt.Errorf("serial port error: %v", err)
	}

	return nil
}

// Read reads data from the serial port
func (sm *SerialManager) Read() ([]byte, error) {
	if sm.SerialPort == nil {
		return nil, fmt.Errorf("serial port not initialized")
	}

	buf := make([]byte, 1024)
	n, err := sm.SerialPort.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// Disconnect closes the serial connection
func (sm *SerialManager) Disconnect() {
	if sm.SerialPort != nil {
		sm.SerialPort.Close()
	}
}

// WaitForBoot waits for the device to boot and be ready for commands
func (sm *SerialManager) WaitForBoot() {
	fmt.Printf("%s[+] Waiting for device to boot (%d seconds)...%s\n", Cyan(""), sm.Config.BootWaitTime, Reset(""))
	time.Sleep(time.Duration(sm.Config.BootWaitTime) * time.Second)

	// Try to establish communication with the device
	maxRetries := 5
	retryDelay := 5 // seconds

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Send a simple command to check if device is responsive
		sm.SendCommand("")
		// Try to get a response from ls /bin
		response := sm.SendCommand("ls /bin")
		if response != "" {
			log.Println("Device is responsive and ready for commands")
			fmt.Printf("%s[+] Device boot wait complete.%s\n", Cyan(""), Reset(""))
			return
		}

		if attempt < maxRetries-1 {
			fmt.Printf("%s[!] Device not ready, waiting %d seconds...%s\n", Yellow(""), retryDelay, Reset(""))
			time.Sleep(time.Duration(retryDelay) * time.Second)
		}
	}

	panic("Device failed to become responsive after boot")
}

// SendCommand sends a command to the device and return the response
func (sm *SerialManager) SendCommand(command string) string {
	if sm.SerialPort == nil {
		panic("Serial port not initialized")
	}

	// Write the command
	_, err := sm.SerialPort.Write([]byte(command + "\r\n"))
	if err != nil {
		log.Printf("Error writing to serial port: %v", err)
		return ""
	}

	// Wait for the command to be processed
	time.Sleep(time.Duration(sm.Config.CommandDelay) * time.Second)

	// Read the response
	var output strings.Builder
	buf := make([]byte, 1024)

	// Read with timeout
	// Note: The serial.Port type doesn't have SetReadTimeout, so we'll use a different approach

	// Set a deadline for reading
	deadline := time.Now().Add(sm.Config.Timeout)

	for time.Now().Before(deadline) {
		n, err := sm.SerialPort.Read(buf)
		if err != nil {
			log.Printf("Error reading from serial port: %v", err)
			break
		}

		if n > 0 {
			output.Write(buf[:n])
		}

		// Small delay between reads
		time.Sleep(time.Duration(sm.Config.ReadDelay) * time.Millisecond)
	}

	return strings.TrimSpace(output.String())
}

// ProcessMonitor handles process monitoring and display
type ProcessMonitor struct {
	SerialManager *SerialManager
	Classifier    *CommandClassifier
}

// NewProcessMonitor creates a new ProcessMonitor
func NewProcessMonitor() *ProcessMonitor {
	return &ProcessMonitor{
		Classifier: NewCommandClassifier(),
	}
}

// GetProcessList gets and formats the process list
func (pm *ProcessMonitor) GetProcessList() [][]string {
	psOutput := pm.SerialManager.SendCommand("ps")
	lines := strings.Split(psOutput, "\n")

	var data [][]string
	for _, line := range lines {
		process := strings.TrimSpace(line)
		if process != "" && process[0] >= '0' && process[0] <= '9' {
			fields := strings.Fields(process)
			if len(fields) >= 5 {
				pid := fields[0]
				user := fields[1]
				cmd := strings.Join(fields[4:], " ")
				description, _ := pm.Classifier.ClassifyCommand(cmd, nil)
				data = append(data, []string{pid, user, cmd, description})
			}
		}
	}

	return data
}

// DisplayProcessList displays the process list in a formatted table
func (pm *ProcessMonitor) DisplayProcessList() {
	data := pm.GetProcessList()
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	if len(data) > 0 {
		fmt.Printf("\n%s=== Process List (Timestamp: %s) ===%s\n", Cyan(""), timestamp, Reset(""))

		// Print header
		fmt.Printf("%-8s %-10s %-30s %s\n", "PID", "USER", "CMD", "Description")
		fmt.Println(strings.Repeat("-", 80))

		// Print data
		for _, row := range data {
			pid, user, cmd, desc := row[0], row[1], row[2], row[3]
			fmt.Printf("%-8s %-10s %-30s %s\n", pid, user, cmd, desc)
		}
	} else {
		fmt.Printf("%s[!] No valid process data collected.%s\n", Yellow(""), Reset(""))
	}
}

// GenerateProcessReport generates a Markdown formatted process list for the report
func (pm *ProcessMonitor) GenerateProcessReport(data [][]string, timestamp string) string {
	if len(data) == 0 {
		return "No process data available."
	}

	var report strings.Builder
	report.WriteString("## Process List\n\n")
	report.WriteString(fmt.Sprintf("**Timestamp:** %s\n\n", timestamp))
	report.WriteString("| PID | USER | CMD | Description |\n")
	report.WriteString("|-----|------|-----|-------------|\n")

	for _, row := range data {
		pid, user, cmd, desc := row[0], row[1], row[2], row[3]
		// Escape any pipe characters in the data
		cmd = strings.ReplaceAll(cmd, "|", "\\|")
		desc = strings.ReplaceAll(desc, "|", "\\|")
		report.WriteString(fmt.Sprintf("| %s | %s | `%s` | %s |\n", pid, user, cmd, desc))
	}

	return report.String()
}

// CommandMenu handles command menu and execution
type CommandMenu struct {
	SerialManager *SerialManager
	Classifier    *CommandClassifier
	MenuItems     []string
}

// NewCommandMenu creates a new CommandMenu
func NewCommandMenu(serialManager *SerialManager) *CommandMenu {
	cm := &CommandMenu{
		SerialManager: serialManager,
		Classifier:    NewCommandClassifier(),
		MenuItems:     []string{},
	}

	cm.InitializeMenu()
	return cm
}

// InitializeMenu initializes the command menu
func (cm *CommandMenu) InitializeMenu() {
	binOutput := cm.SerialManager.SendCommand("ls /bin")
	if binOutput == "" {
		log.Println("No output from 'ls /bin'")
		panic("Failed to get /bin contents")
	}

	// Clean the output and extract valid commands
	cleanOutput := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`).ReplaceAllString(binOutput, "")

	// Split by whitespace and newlines, then filter out empty strings
	var commands []string
	for _, line := range strings.Split(cleanOutput, "\n") {
		// Split the line by whitespace and filter out empty strings
		lineCommands := strings.Fields(line)
		// Filter out directory names and invalid commands
		for _, cmd := range lineCommands {
			cmd = strings.TrimSpace(cmd)
			// Skip if it's a directory name or path
			if strings.HasPrefix(cmd, "/") || cmd == "bin" {
				continue
			}
			// Skip if it contains invalid characters
			if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(cmd) {
				continue
			}
			commands = append(commands, cmd)
		}
	}

	if len(commands) == 0 {
		log.Println("No valid commands found in /bin")
		panic("No valid commands found in /bin")
	}

	// Remove duplicates and sort
	uniqueCommands := make(map[string]bool)
	for _, cmd := range commands {
		uniqueCommands[cmd] = true
	}

	cm.MenuItems = make([]string, 0, len(uniqueCommands))
	for cmd := range uniqueCommands {
		cm.MenuItems = append(cm.MenuItems, cmd)
	}

	// Sort the menu items
	for i := 0; i < len(cm.MenuItems); i++ {
		for j := i + 1; j < len(cm.MenuItems); j++ {
			if cm.MenuItems[i] > cm.MenuItems[j] {
				cm.MenuItems[i], cm.MenuItems[j] = cm.MenuItems[j], cm.MenuItems[i]
			}
		}
	}

	log.Printf("Found %d valid commands in /bin", len(cm.MenuItems))
}

// DisplayMenu displays the command menu
func (cm *CommandMenu) DisplayMenu() {
	fmt.Printf("\n%s[+] Enabled Commands in /bin:%s\n", Cyan(""), Reset(""))
	for i, cmd := range cm.MenuItems {
		if cm.Classifier.StandardCommands[cmd] {
			fmt.Printf("%s%d. %s (Standard Command)%s\n", Green(""), i+1, cmd, Reset(""))
		} else {
			fmt.Printf("%s%d. %s (Non-Standard)%s\n", Red(""), i+1, cmd, Reset(""))
		}
	}
}

// ExecuteCommand executes the selected command
func (cm *CommandMenu) ExecuteCommand(choice string) bool {
	if choice == "q" {
		return false
	}

	choiceIdx, err := strconv.Atoi(choice)
	if err != nil {
		fmt.Printf("%s[!] Invalid input. Please enter a number or 'q' to quit.%s\n", Yellow(""), Reset(""))
		return true
	}

	choiceIdx-- // Convert to 0-based index

	if choiceIdx >= 0 && choiceIdx < len(cm.MenuItems) {
		selectedCmd := cm.MenuItems[choiceIdx]
		fmt.Printf("\n%s[+] Running command: %s%s\n", Cyan(""), selectedCmd, Reset(""))
		output := cm.SerialManager.SendCommand(selectedCmd)
		fmt.Printf("%s[+] Output:%s\n", Cyan(""), Reset(""))
		if output != "" {
			fmt.Println(output)
		} else {
			fmt.Println("No output received.")
		}
	} else {
		fmt.Printf("%s[!] Invalid choice. Please select a number between 1 and %d.%s\n", Yellow(""), len(cm.MenuItems), Reset(""))
	}

	return true
}

// DisplayBanner displays the application banner
func DisplayBanner() {
	// Define the banner without any indentation
	bannerLines := []string{
		"      ____    ______   _____                  __ ",
		"     /  _/___/_  __/  / ___/_________  __  __/ /_",
		"     / // __ \\/ /     \\__ \\/ ___/ __ \\/ / / / __/",
		"   _/ // /_/ / /     ___/ / /__/ /_/ / /_/ / /_  ",
		"  /___/\\____/_/     /____/\\___/\\____/\\__,_/\\__/  ",
		"                                             ",
		"",
		"Author: Darkma773r (https://github.com/darkmatter91)",
		"",
	}

	// Add padding to match menu alignment
	padding := 2

	// Print each line with consistent padding
	for _, line := range bannerLines {
		fmt.Printf("%s%s%s\n", strings.Repeat(" ", padding), Cyan(line), Reset())
	}
}

// DisplayStartupMenu displays the startup menu and get user choice
func DisplayStartupMenu() int {
	fmt.Printf("\n%s=== IoT Scout Startup Menu ===%s\n", Cyan(""), Reset(""))
	fmt.Printf("%s1. Capture live from UART%s\n", Cyan(""), Reset(""))
	fmt.Printf("%s2. Recon from local firmware%s\n", Cyan(""), Reset(""))
	fmt.Printf("%s3. Search for sensitive information%s\n", Cyan(""), Reset(""))

	for {
		fmt.Printf("\n%sEnter your choice (1-3): %s", Cyan(""), Reset(""))
		var choice int
		fmt.Scanf("%d", &choice)

		if choice >= 1 && choice <= 3 {
			return choice
		}
		fmt.Printf("%s[!] Invalid choice. Please enter 1, 2, or 3.%s\n", Yellow(""), Reset(""))
	}
}

// pathCompleter provides path completion suggestions
func pathCompleter(d prompt.Document) []prompt.Suggest {
	path := d.GetWordBeforeCursor()

	// If path is empty, start from current directory
	if path == "" {
		path = "."
	}

	// Get the directory and file prefix
	dir := filepath.Dir(path)
	if dir == "." && !strings.HasPrefix(path, ".") {
		dir = path
	}

	// If the path ends with separator, we need to list the directory content
	if strings.HasSuffix(path, string(os.PathSeparator)) {
		dir = path
	}

	files, _ := ioutil.ReadDir(dir)
	var suggestions []prompt.Suggest

	for _, f := range files {
		name := f.Name()
		fullPath := filepath.Join(dir, name)

		// Add trailing slash for directories
		if f.IsDir() {
			name += string(os.PathSeparator)
			fullPath += string(os.PathSeparator)
		}

		suggestions = append(suggestions, prompt.Suggest{
			Text:        fullPath,
			Description: fmt.Sprintf("%s, %d bytes", f.Mode().String(), f.Size()),
		})
	}

	return prompt.FilterHasPrefix(suggestions, path, true)
}

// GetUserInput gets user input with a prompt and returns the cleaned input
func GetUserInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		PrintStatus("error", fmt.Sprintf("Error reading input: %v", err))
		return ""
	}

	// Clean the input by removing carriage returns and trimming whitespace
	return strings.TrimSpace(strings.ReplaceAll(input, "\r", ""))
}

// GetFirmwarePath gets the path to the firmware directory
func GetFirmwarePath() string {
	path := GetUserInput(fmt.Sprintf("%s[?]%s Enter path to firmware file (e.g., firmware.bin): ",
		Blue(""), Reset()))

	path = strings.TrimSpace(path)
	if path == "" {
		PrintStatus("warning", "No path provided.")
		return ""
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		PrintStatus("error", fmt.Sprintf("Path does not exist: %s", path))
		return ""
	}

	return path
}

// LocalFirmwareAnalyzer handles firmware analysis
type LocalFirmwareAnalyzer struct {
	FirmwarePath   string
	ExtractedPath  string
	BinDirectories []string
	BinaryAnalysis map[string]string
	IotBinaries    map[string]string
}

// NewLocalFirmwareAnalyzer creates a new LocalFirmwareAnalyzer
func NewLocalFirmwareAnalyzer(firmwarePath string) *LocalFirmwareAnalyzer {
	return &LocalFirmwareAnalyzer{
		FirmwarePath:   firmwarePath,
		ExtractedPath:  "",
		BinDirectories: []string{},
		BinaryAnalysis: make(map[string]string),
		IotBinaries:    make(map[string]string),
	}
}

// ExtractFirmware extracts the firmware using binwalk and jefferson
func (lfa *LocalFirmwareAnalyzer) ExtractFirmware() error {
	fmt.Printf("%s[+] Extracting firmware using binwalk...%s\n", Cyan(""), Reset(""))

	// Create extraction directory
	extractDir := filepath.Join(filepath.Dir(lfa.FirmwarePath), "extracted_"+filepath.Base(lfa.FirmwarePath))
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("failed to create extraction directory: %v", err)
	}

	// Run binwalk to extract files
	cmd := exec.Command("binwalk", "-e", "-q", lfa.FirmwarePath)
	cmd.Dir = extractDir
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("binwalk extraction failed: %v", err)
	}

	fmt.Printf("%s[✓] Binwalk extraction complete%s\n", Green(""), Reset())

	// Try to extract squashfs if present
	fmt.Printf("%s[+] Attempting to extract squashfs filesystems...%s\n", Cyan(""), Reset(""))

	// Find all extracted files
	var extractedFiles []string
	err := filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			extractedFiles = append(extractedFiles, path)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to list extracted files: %v", err)
	}

	// Try to extract each file with jefferson
	for _, file := range extractedFiles {
		// Check if file is a squashfs
		cmd = exec.Command("file", file)
		output, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}

		if strings.Contains(string(output), "Squashfs filesystem") {
			fmt.Printf("%s[+] Found squashfs filesystem: %s%s\n", Green(""), file, Reset(""))

			// Create output directory for this squashfs
			squashfsDir := file + "_squashfs"
			if err := os.MkdirAll(squashfsDir, 0755); err != nil {
				fmt.Printf("%s[!] Failed to create squashfs output directory: %v%s\n", Yellow(""), err, Reset(""))
				continue
			}

			// Extract with jefferson
			cmd = exec.Command("jefferson", file, "-d", squashfsDir)
			output, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Printf("%s[!] Jefferson extraction failed for %s: %v%s\n", Yellow(""), err, Reset(""))
				fmt.Printf("%s[!] Jefferson output:%s\n%s\n", Yellow(""), Reset(""), string(output))
				continue
			}

			fmt.Printf("%s[+] Successfully extracted squashfs: %s%s\n", Green(""), file, Reset(""))
			fmt.Printf("%s[+] Jefferson output:%s\n%s\n", Cyan(""), Reset(""), string(output))
		}
	}

	// Find the main extracted directory (usually _firmware.bin.extracted)
	var mainExtractedDir string
	err = filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && strings.Contains(path, ".extracted") {
			mainExtractedDir = path
			return filepath.SkipDir
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to find main extracted directory: %v", err)
	}

	if mainExtractedDir == "" {
		return fmt.Errorf("no extracted directory found")
	}

	lfa.ExtractedPath = mainExtractedDir
	fmt.Printf("%s[+] Using extracted directory: %s%s\n", Green(""), mainExtractedDir, Reset(""))

	return nil
}

// FindBinDirectories finds all bin directories in the firmware
func (lfa *LocalFirmwareAnalyzer) FindBinDirectories() []string {
	fmt.Printf("%s[+] Searching for bin directories in firmware...%s\n", Cyan(""), Reset(""))

	var binDirs []string

	// Use the extracted path if available, otherwise use the original firmware path
	searchPath := lfa.FirmwarePath
	if lfa.ExtractedPath != "" {
		searchPath = lfa.ExtractedPath
	}

	err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && (info.Name() == "bin" || info.Name() == "sbin" || info.Name() == "usr/bin" || info.Name() == "usr/sbin") {
			binDirs = append(binDirs, path)
			fmt.Printf("%s[+] Found bin directory: %s%s\n", Green(""), path, Reset(""))
		}

		return nil
	})

	if err != nil {
		log.Printf("Error walking firmware directory: %v", err)
		fmt.Printf("%s[!] Error searching for bin directories: %v%s\n", Yellow(""), err, Reset(""))
	}

	lfa.BinDirectories = binDirs
	return binDirs
}

// AnalyzeBinDirectories analyzes the contents of bin directories
func (lfa *LocalFirmwareAnalyzer) AnalyzeBinDirectories() map[string]string {
	fmt.Printf("%s[+] Analyzing bin directories...%s\n", Cyan(""), Reset(""))

	analysis := make(map[string]string)

	for _, binDir := range lfa.BinDirectories {
		err := filepath.Walk(binDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if !info.IsDir() {
				relPath, _ := filepath.Rel(lfa.FirmwarePath, path)
				fileType := lfa.analyzeFile(path)
				analysis[relPath] = fileType
				fmt.Printf("%s[+] Analyzed: %s - %s%s\n", Green(""), relPath, fileType, Reset(""))
			}

			return nil
		})

		if err != nil {
			log.Printf("Error analyzing bin directory %s: %v", binDir, err)
			fmt.Printf("%s[!] Error analyzing bin directory %s: %v%s\n", Yellow(""), binDir, err, Reset(""))
		}
	}

	lfa.BinaryAnalysis = analysis
	return analysis
}

// FindCommonIotBinaries searches for common IoT binaries
func (lfa *LocalFirmwareAnalyzer) FindCommonIotBinaries() map[string]string {
	fmt.Printf("%s[+] Searching for common IoT binaries...%s\n", Cyan(""), Reset(""))

	commonBinaries := map[string]string{
		"dropbear":       "SSH server",
		"httpd":          "HTTP server",
		"dhcpd":          "DHCP server",
		"wpa_supplicant": "Wi-Fi client",
		"hostapd":        "Wi-Fi access point",
		"dnsmasq":        "DNS and DHCP server",
		"ntpd":           "NTP daemon",
		"sshd":           "SSH server",
		"telnetd":        "Telnet server",
		"ftpd":           "FTP server",
		"tftpd":          "TFTP server",
		"smbd":           "Samba server",
		"nmbd":           "NetBIOS name server",
		"upnpd":          "UPnP daemon",
		"avahi-daemon":   "mDNS/DNS-SD daemon",
		"busybox":        "Multi-call binary",
		"init":           "Init process",
		"systemd":        "System and service manager",
		"udevd":          "Device manager",
		"dbus-daemon":    "Message bus daemon",
		"syslogd":        "System logging daemon",
		"klogd":          "Kernel logging daemon",
		"crond":          "Cron daemon",
		"watchdog":       "Hardware watchdog",
		"iptables":       "Firewall",
		"ip6tables":      "IPv6 firewall",
		"ebtables":       "Ethernet bridge firewall",
		"brctl":          "Ethernet bridge configuration",
		"iwconfig":       "Wireless configuration",
		"iwlist":         "Wireless scanning",
		"iwpriv":         "Wireless private commands",
		"wpa_cli":        "Wi-Fi control interface",
		"wpa_passphrase": "Wi-Fi passphrase generator",
		"rfkill":         "RF kill switch control",
		"flash":          "Flash memory tools",
		"mtd":            "Memory Technology Device tools",
		"nvram":          "Non-volatile RAM tools",
		"ubootenv":       "U-Boot environment tools",
		"factorydefault": "Factory reset tool",
		"firstboot":      "First boot configuration",
		"led":            "LED control",
		"gpio":           "GPIO control",
		"i2c":            "I2C tools",
		"i2cdetect":      "I2C bus detection",
		"i2cdump":        "I2C bus dump",
		"i2cget":         "I2C register read",
		"i2cset":         "I2C register write",
	}

	found := make(map[string]string)

	for _, binDir := range lfa.BinDirectories {
		err := filepath.Walk(binDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if !info.IsDir() {
				binName := info.Name()
				if desc, exists := commonBinaries[binName]; exists {
					relPath, _ := filepath.Rel(lfa.FirmwarePath, path)
					found[relPath] = desc
					fmt.Printf("%s[+] Found IoT binary: %s - %s%s\n", Green(""), relPath, desc, Reset(""))
				}
			}

			return nil
		})

		if err != nil {
			log.Printf("Error searching for IoT binaries in %s: %v", binDir, err)
			fmt.Printf("%s[!] Error searching for IoT binaries in %s: %v%s\n", Yellow(""), binDir, err, Reset(""))
		}
	}

	lfa.IotBinaries = found
	return found
}

// analyzeFile analyzes a file to determine its type
func (lfa *LocalFirmwareAnalyzer) analyzeFile(path string) string {
	// Try to read the file header
	file, err := os.Open(path)
	if err != nil {
		return "Error: " + err.Error()
	}
	defer file.Close()

	// Read the first 4 bytes
	header := make([]byte, 4)
	_, err = file.Read(header)
	if err != nil {
		return "Error reading file: " + err.Error()
	}

	// Check for ELF header (0x7F 'E' 'L' 'F')
	if header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		return "ELF binary"
	}

	// Check for script header (#!)
	if header[0] == '#' && header[1] == '!' {
		return "Script"
	}

	// Check for ASCII text
	isText := true
	for _, b := range header {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			isText = false
			break
		}
	}

	if isText {
		return "Text file"
	}

	return "Binary file"
}

// DisplayAnalysis displays the firmware analysis results
func (lfa *LocalFirmwareAnalyzer) DisplayAnalysis() {
	PrintSection("Firmware Analysis Results")

	// Display Bin Directories
	PrintTableHeader("Bin Directories")
	if len(lfa.BinDirectories) > 0 {
		for _, dir := range lfa.BinDirectories {
			relPath, _ := filepath.Rel(lfa.FirmwarePath, dir)
			PrintTableRow(relPath)
		}
	} else {
		PrintTableRow("No bin directories found")
	}
	PrintTableFooter(1)

	// Display Binary Analysis
	PrintTableHeader("Path", "Type")
	if len(lfa.BinaryAnalysis) > 0 {
		for path, fileType := range lfa.BinaryAnalysis {
			PrintTableRow(path, fileType)
		}
	} else {
		PrintTableRow("No binaries analyzed", "")
	}
	PrintTableFooter(2)

	// Display IoT Binaries
	PrintTableHeader("Path", "Description")
	if len(lfa.IotBinaries) > 0 {
		for path, desc := range lfa.IotBinaries {
			PrintTableRow(path, desc)
		}
	} else {
		PrintTableRow("No IoT binaries found", "")
	}
	PrintTableFooter(2)
}

// GenerateFirmwareReport generates a Markdown formatted firmware analysis report
func (lfa *LocalFirmwareAnalyzer) GenerateFirmwareReport(timestamp string) string {
	var report strings.Builder

	report.WriteString("## Firmware Analysis\n\n")
	report.WriteString(fmt.Sprintf("**Timestamp:** %s\n\n", timestamp))

	// Bin Directories section
	report.WriteString("### Bin Directories\n\n")
	if len(lfa.BinDirectories) > 0 {
		for _, dir := range lfa.BinDirectories {
			relPath, _ := filepath.Rel(lfa.FirmwarePath, dir)
			report.WriteString(fmt.Sprintf("- `%s`\n", relPath))
		}
	} else {
		report.WriteString("No bin directories found.\n")
	}
	report.WriteString("\n")

	// Binary Analysis section
	report.WriteString("### Binary Analysis\n\n")
	if len(lfa.BinaryAnalysis) > 0 {
		report.WriteString("| Path | Type |\n")
		report.WriteString("|------|------|\n")
		for path, fileType := range lfa.BinaryAnalysis {
			// Escape any pipe characters in the data
			path = strings.ReplaceAll(path, "|", "\\|")
			fileType = strings.ReplaceAll(fileType, "|", "\\|")
			report.WriteString(fmt.Sprintf("| `%s` | %s |\n", path, fileType))
		}
	} else {
		report.WriteString("No binaries analyzed.\n")
	}
	report.WriteString("\n")

	// IoT Binaries section
	report.WriteString("### IoT Binaries\n\n")
	if len(lfa.IotBinaries) > 0 {
		report.WriteString("| Path | Description |\n")
		report.WriteString("|------|-------------|\n")
		for path, desc := range lfa.IotBinaries {
			// Escape any pipe characters in the data
			path = strings.ReplaceAll(path, "|", "\\|")
			desc = strings.ReplaceAll(desc, "|", "\\|")
			report.WriteString(fmt.Sprintf("| `%s` | %s |\n", path, desc))
		}
	} else {
		report.WriteString("No IoT binaries found.\n")
	}
	report.WriteString("\n")

	return report.String()
}

// AnalyzeFirmware performs a complete firmware analysis
func (lfa *LocalFirmwareAnalyzer) AnalyzeFirmware() (map[string]string, map[string]string, error) {
	// Extract firmware first
	if err := lfa.ExtractFirmware(); err != nil {
		fmt.Printf("%s[!] Error extracting firmware: %v%s\n", Yellow(""), err, Reset(""))
		// Continue with original firmware if extraction fails
	}

	// Find bin directories
	lfa.FindBinDirectories()

	// Analyze bin directories
	lfa.AnalyzeBinDirectories()

	// Find common IoT binaries
	lfa.FindCommonIotBinaries()

	// Display analysis results
	lfa.DisplayAnalysis()

	return lfa.BinaryAnalysis, lfa.IotBinaries, nil
}

// SensitivePatterns defines patterns to search for in files
var SensitivePatterns = map[string]struct {
	pattern  string
	category string
}{
	"password": {
		pattern:  "\\b(?i)(pass(word)?|pwd)\\s*[=:]\\s*[^\\s]+\\b",
		category: "Passwords",
	},
	"api_key": {
		pattern:  "\\b(?i)(api[_-]?key|apikey)\\s*[=:]\\s*[^\\s]+\\b",
		category: "API Keys",
	},
	"token": {
		pattern:  "\\b(?i)(token|access_token|refresh_token)\\s*[=:]\\s*[^\\s]+\\b",
		category: "Tokens",
	},
	"secret": {
		pattern:  "\\b(?i)(secret|private_key)\\s*[=:]\\s*[^\\s]+\\b",
		category: "Secrets",
	},
	"email": {
		pattern:  "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
		category: "Contact Information",
	},
	"ip_address": {
		pattern:  "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b",
		category: "Network Information",
	},
	"mac_address": {
		pattern:  "\\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\\b",
		category: "Network Information",
	},
	"url": {
		pattern:  "\\bhttps?://[^\\s<>\"']+|www\\.[^\\s<>\"']+\\b",
		category: "URLs",
	},
	"ssh_key": {
		pattern:  "-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
		category: "SSH Keys",
	},
	"certificate": {
		pattern:  "-----BEGIN CERTIFICATE-----",
		category: "Certificates",
	},
	"user": {
		pattern:  "\\b(?i)(user(name)?|login)\\s*[=:]\\s*[^\\s]+\\b",
		category: "User Information",
	},
}

// ExcludedExtensions are file extensions to skip during search
var ExcludedExtensions = []string{
	".py", ".go", ".js", ".java", ".c", ".cpp", ".h", ".hpp",
	".cs", ".rb", ".php", ".html", ".css", ".md", ".txt",
}

// CommentIndicators are strings that indicate code comments
var CommentIndicators = []string{
	"#", "//", "/*", "*/", "--", "<!--", "-->",
}

// SearchSensitiveFiles searches for sensitive information in files
func (lfa *LocalFirmwareAnalyzer) SearchSensitiveFiles() (map[string]map[string][]string, error) {
	fmt.Printf("%s[+] Searching for sensitive information...%s\n", Cyan(""), Reset())

	findings := make(map[string]map[string][]string)

	// Use the extracted path if available, otherwise use the original firmware path
	searchPath := lfa.FirmwarePath
	if lfa.ExtractedPath != "" {
		searchPath = lfa.ExtractedPath
		fmt.Printf("%s[+] Using extracted path for search: %s%s\n", Green(""), searchPath, Reset(""))
	}

	// First, search for common sensitive file patterns
	sensitiveFilePatterns := []string{
		"passwd", "shadow", "htpasswd", "htaccess", ".env", "config.json",
		"config.yml", "config.xml", ".conf", ".cfg", ".ini", ".properties",
		".pem", ".key", ".crt", ".pfx", ".p12", ".keystore", ".jks",
		".pwd", ".pass", ".cred", ".auth", ".secret", ".token", ".api",
		".credential", ".password", ".passwd", ".shadow", ".htpasswd",
		".gitconfig", ".netrc", ".aws", ".azure", ".gcloud", ".kubeconfig",
		".docker", ".npmrc", ".yarnrc", ".pip", ".gem", ".maven", ".gradle",
		".sbt", ".nuget", ".composer", ".bower",
	}

	fmt.Printf("%s[+] Searching for sensitive file patterns...%s\n", Cyan(""), Reset())

	for _, pattern := range sensitiveFilePatterns {
		err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			if strings.Contains(strings.ToLower(info.Name()), pattern) {
				relPath, _ := filepath.Rel(lfa.FirmwarePath, path)
				if findings[relPath] == nil {
					findings[relPath] = make(map[string][]string)
				}

				// Read and display content of sensitive files
				content, err := lfa.tryReadFile(path)
				if err == nil {
					// For passwd and shadow files, show the content
					if pattern == "passwd" || pattern == "shadow" {
						findings[relPath]["Sensitive Files"] = append(findings[relPath]["Sensitive Files"],
							fmt.Sprintf("Sensitive file pattern: %s\nContent:\n%s", pattern, content))
					} else {
						findings[relPath]["Sensitive Files"] = append(findings[relPath]["Sensitive Files"],
							fmt.Sprintf("Sensitive file pattern: %s", pattern))
					}
				} else {
					findings[relPath]["Sensitive Files"] = append(findings[relPath]["Sensitive Files"],
						fmt.Sprintf("Sensitive file pattern: %s (Could not read content)", pattern))
				}

				fmt.Printf("%s[+] Found sensitive file: %s%s\n", Green(""), relPath, Reset(""))
			}

			return nil
		})

		if err != nil {
			fmt.Printf("%s[!] Error searching for pattern %s: %v%s\n", Yellow(""), pattern, err, Reset(""))
		}
	}

	// Now search for sensitive content in all files
	fmt.Printf("%s[+] Searching for sensitive content in files...%s\n", Cyan(""), Reset())

	err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Skip files with excluded extensions
		ext := strings.ToLower(filepath.Ext(path))
		for _, excludedExt := range ExcludedExtensions {
			if ext == excludedExt {
				return nil
			}
		}

		// Skip files that are too large (likely binaries)
		if info.Size() > 1024*1024 { // Skip files larger than 1MB
			return nil
		}

		// Try to read the file
		content, err := lfa.tryReadFile(path)
		if err != nil {
			return nil
		}

		// Skip if file is likely code or comment
		if lfa.isLikelyCodeOrComment(content) {
			return nil
		}

		// Search for patterns
		for patternName, patternInfo := range SensitivePatterns {
			re := regexp.MustCompile(patternInfo.pattern)
			matches := re.FindAllString(content, -1)
			if len(matches) > 0 {
				relPath, _ := filepath.Rel(lfa.FirmwarePath, path)
				if findings[relPath] == nil {
					findings[relPath] = make(map[string][]string)
				}

				// Include the actual matches in the findings
				matchInfo := fmt.Sprintf("%s (%d matches):\n%s",
					patternName,
					len(matches),
					strings.Join(matches, "\n"))

				findings[relPath][patternInfo.category] = append(findings[relPath][patternInfo.category], matchInfo)
				fmt.Printf("%s[+] Found %s in %s (%d matches)%s\n",
					Green(""), patternInfo.category, relPath, len(matches), Reset(""))
			}
		}

		return nil
	})

	if err != nil {
		log.Printf("Error searching for sensitive information: %v", err)
		fmt.Printf("%s[!] Error searching for sensitive information: %v%s\n", Yellow(""), err, Reset(""))
		return nil, err
	}

	if len(findings) == 0 {
		fmt.Printf("%s[!] No sensitive information found.%s\n", Yellow(""), Reset(""))
	} else {
		fmt.Printf("%s[+] Found sensitive information in %d files.%s\n", Green(""), len(findings), Reset(""))

		// Display categorized findings
		fmt.Printf("\n%s=== Categorized Findings ===%s\n", Cyan(""), Reset(""))
		for file, categories := range findings {
			fmt.Printf("\n%sFile: %s%s\n", Blue(""), file, Reset(""))
			for category, items := range categories {
				fmt.Printf("  %s%s:%s\n", Yellow(""), category, Reset(""))
				for _, item := range items {
					fmt.Printf("    - %s\n", item)
				}
			}
		}
	}

	return findings, nil
}

// tryReadFile attempts to read a file with different encodings
func (lfa *LocalFirmwareAnalyzer) tryReadFile(path string) (string, error) {
	// Try to read the file
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}

	// Try to decode with Windows-1252 encoding (common in embedded systems)
	decoder := charmap.Windows1252.NewDecoder()
	decoded, err := decoder.Bytes(content)
	if err == nil {
		return string(decoded), nil
	}

	// If decoding fails, return raw content
	return string(content), nil
}

// isLikelyCodeOrComment checks if content is likely code or comment
func (lfa *LocalFirmwareAnalyzer) isLikelyCodeOrComment(content string) bool {
	// Check for comment indicators
	for _, indicator := range CommentIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}

	// Check for common code patterns
	codePatterns := []string{
		"function", "class", "import", "package", "return",
		"if ", "else ", "for ", "while ", "switch ",
		"public", "private", "protected", "static",
	}

	for _, pattern := range codePatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}

	return false
}

// ReportGenerator handles report generation
type ReportGenerator struct {
	Timestamp         string
	ProcessList       [][]string
	FirmwareAnalysis  map[string]string
	IotBinaries       map[string]string
	SensitiveFindings map[string]map[string][]string
}

// NewReportGenerator creates a new ReportGenerator
func NewReportGenerator() *ReportGenerator {
	return &ReportGenerator{
		Timestamp:         time.Now().Format("2006-01-02 15:04:05"),
		ProcessList:       make([][]string, 0),
		FirmwareAnalysis:  make(map[string]string),
		IotBinaries:       make(map[string]string),
		SensitiveFindings: make(map[string]map[string][]string),
	}
}

// GenerateReport generates a comprehensive report
func (rg *ReportGenerator) GenerateReport() string {
	var report strings.Builder

	// Header with better spacing
	report.WriteString("# IoT Scout Analysis Report\n\n")
	report.WriteString(fmt.Sprintf("**Generated:** %s\n\n", rg.Timestamp))
	report.WriteString("---\n\n")

	// Process List with better formatting
	report.WriteString("## Process List\n\n")
	if len(rg.ProcessList) > 0 {
		report.WriteString("| PID | USER | CMD | Description |\n")
		report.WriteString("|-----|------|-----|-------------|\n")
		for _, process := range rg.ProcessList {
			if len(process) >= 4 {
				// Escape pipe characters and add proper spacing
				cmd := strings.ReplaceAll(process[2], "|", "\\|")
				desc := strings.ReplaceAll(process[3], "|", "\\|")
				report.WriteString(fmt.Sprintf("| %s | %s | `%s` | %s |\n",
					process[0], process[1], cmd, desc))
			}
		}
	} else {
		report.WriteString("*No process data available.*\n")
	}
	report.WriteString("\n---\n\n")

	// Firmware Analysis with better section separation
	report.WriteString("## Firmware Analysis\n\n")
	if len(rg.FirmwareAnalysis) > 0 {
		report.WriteString("### Binary Files Found\n\n")
		report.WriteString("| Path | Type |\n")
		report.WriteString("|------|------|\n")
		for path, fileType := range rg.FirmwareAnalysis {
			// Escape pipe characters and format paths as code
			path = strings.ReplaceAll(path, "|", "\\|")
			fileType = strings.ReplaceAll(fileType, "|", "\\|")
			report.WriteString(fmt.Sprintf("| `%s` | %s |\n", path, fileType))
		}
	} else {
		report.WriteString("*No firmware analysis data available.*\n")
	}
	report.WriteString("\n---\n\n")

	// IoT Binaries with better formatting
	report.WriteString("## IoT Binaries\n\n")
	if len(rg.IotBinaries) > 0 {
		report.WriteString("### Common IoT Components Identified\n\n")
		report.WriteString("| Path | Description |\n")
		report.WriteString("|------|-------------|\n")
		for path, desc := range rg.IotBinaries {
			// Escape pipe characters and format paths as code
			path = strings.ReplaceAll(path, "|", "\\|")
			desc = strings.ReplaceAll(desc, "|", "\\|")
			report.WriteString(fmt.Sprintf("| `%s` | %s |\n", path, desc))
		}
	} else {
		report.WriteString("*No IoT binaries found.*\n")
	}
	report.WriteString("\n---\n\n")

	// Sensitive Information with better organization
	report.WriteString("## Sensitive Information\n\n")
	if len(rg.SensitiveFindings) > 0 {
		for file, categories := range rg.SensitiveFindings {
			report.WriteString(fmt.Sprintf("### File: `%s`\n\n", file))

			// Handle sensitive file patterns first
			if patterns, ok := categories["Sensitive Files"]; ok {
				report.WriteString("#### Sensitive File Patterns\n\n")
				for _, pattern := range patterns {
					report.WriteString(fmt.Sprintf("- %s\n", pattern))
				}
				report.WriteString("\n")
			}

			// Handle other categories with better separation
			for category, items := range categories {
				if category != "Sensitive Files" {
					report.WriteString(fmt.Sprintf("#### %s\n\n", category))
					for _, item := range items {
						report.WriteString(fmt.Sprintf("- %s\n", item))
					}
					report.WriteString("\n")
				}
			}
			report.WriteString("---\n\n")
		}
	} else {
		report.WriteString("*No sensitive information found.*\n\n")
	}

	return report.String()
}

// SaveReport saves the report to a file
func (rg *ReportGenerator) SaveReport() error {
	report := rg.GenerateReport()
	filename := fmt.Sprintf("iot_scout_report_%s.md", time.Now().Format("20060102_150405"))

	err := ioutil.WriteFile(filename, []byte(report), 0644)
	if err != nil {
		return fmt.Errorf("error saving report: %v", err)
	}

	fmt.Printf("%s[+] Report saved to %s%s\n", Green(""), filename, Reset(""))
	return nil
}

// PrintMenuHeader prints a formatted menu header
func PrintMenuHeader(title string) {
	width := 60
	border := Magenta(strings.Repeat("═", width))
	fmt.Printf("\n%s\n", border)

	topBorder := Magenta("╔" + strings.Repeat("═", width-2) + "╗")
	fmt.Printf("%s\n", topBorder)

	padding := (width - len(title)) / 2
	titleLine := Magenta("║") + strings.Repeat(" ", padding) + White(title) + strings.Repeat(" ", width-2-padding-len(title)) + Magenta("║")
	fmt.Printf("%s\n", titleLine)

	bottomBorder := Magenta("╚" + strings.Repeat("═", width-2) + "╝")
	fmt.Printf("%s\n", bottomBorder)
}

// PrintMenuItem prints a formatted menu item
func PrintMenuItem(number int, description string, isSelected bool) {
	if isSelected {
		arrow := Green("▶")
		bracket := Green("[" + strconv.Itoa(number) + "]")
		desc := White(description)
		fmt.Printf(" %s %s %s\n", arrow, bracket, desc)
	} else {
		bracket := Cyan("[" + strconv.Itoa(number) + "]")
		desc := description
		fmt.Printf("   %s %s\n", bracket, desc)
	}
}

// PrintMenuFooter prints a formatted menu footer
func PrintMenuFooter() {
	width := 60
	fmt.Printf("%s%s%s\n", Magenta(""), strings.Repeat("═", width), Reset(""))
}

// PrintStatus prints a formatted status message
func PrintStatus(status, message string) {
	switch status {
	case "info":
		fmt.Printf("%s[ℹ]%s %s%s%s\n", Blue(""), Reset(), White(""), message, Reset())
	case "success":
		fmt.Printf("%s[✓]%s %s%s%s\n", Green(""), Reset(), White(""), message, Reset())
	case "warning":
		fmt.Printf("%s[!]%s %s%s%s\n", Yellow(""), Reset(), White(""), message, Reset())
	case "error":
		fmt.Printf("%s[✗]%s %s%s%s\n", Red(""), Reset(), White(""), message, Reset())
	}
}

// PrintSection prints a formatted section header
func PrintSection(title string) {
	width := 60
	fmt.Printf("\n%s%s%s\n", Magenta(""), strings.Repeat("─", width), Reset())
	padding := (width - len(title)) / 2
	fmt.Printf("%s%s%s%s\n",
		Magenta(""),
		strings.Repeat(" ", padding),
		White(title),
		Reset())
	fmt.Printf("%s%s%s\n", Magenta(""), strings.Repeat("─", width), Reset())
}

// PrintTableHeader prints a formatted table header
func PrintTableHeader(headers ...string) {
	// Calculate column widths
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = len(header) + 2 // Add padding
	}

	// Print header
	fmt.Print(Magenta(""))
	fmt.Print("┌")
	for i, width := range widths {
		fmt.Print(strings.Repeat("─", width))
		if i < len(widths)-1 {
			fmt.Print("┬")
		}
	}
	fmt.Println("┐", Reset(""))

	// Print header row
	fmt.Print(Magenta(""))
	fmt.Print("│")
	for i, header := range headers {
		fmt.Printf(" %s%-*s%s │", White(""), widths[i]-1, header, Reset(""))
	}
	fmt.Println(Reset(""))

	// Print separator
	fmt.Print(Magenta(""))
	fmt.Print("├")
	for i, width := range widths {
		fmt.Print(strings.Repeat("─", width))
		if i < len(widths)-1 {
			fmt.Print("┼")
		}
	}
	fmt.Println("┤", Reset(""))
}

// PrintTableRow prints a formatted table row
func PrintTableRow(values ...string) {
	fmt.Print(Magenta(""))
	fmt.Print("│")
	for _, value := range values {
		fmt.Printf(" %s%-*s%s │", White(""), len(value)+1, value, Reset(""))
	}
	fmt.Println(Reset(""))
}

// PrintTableFooter prints a formatted table footer
func PrintTableFooter(columns int) {
	fmt.Print(Magenta(""))
	fmt.Print("└")
	for range make([]int, columns) {
		fmt.Print(strings.Repeat("─", 20))
		if columns > 1 {
			fmt.Print("┴")
		}
	}
	fmt.Println("┘", Reset(""))
}

// Main function to run the IoT Scout application
func main() {
	// Enable color output
	color.NoColor = false

	// Initialize components
	serialManager := NewSerialManager("")
	firmwareAnalyzer := NewLocalFirmwareAnalyzer("")
	reportGenerator := NewReportGenerator()

	// Set up signal handling first
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	// Save initial terminal state only if we're in a terminal
	var oldState *term.State
	if term.IsTerminal(int(os.Stdin.Fd())) {
		var err error
		oldState, err = term.GetState(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Printf("%s[!] Error getting terminal state: %v%s\n", Yellow(""), err, Reset(""))
		}
	}

	// Set up cleanup function
	cleanup := func() {
		if oldState != nil {
			term.Restore(int(os.Stdin.Fd()), oldState)
		}
		PrintStatus("success", "Thank you for using IoT Scout!")
		os.Exit(0)
	}

	// Handle Ctrl+C
	go func() {
		<-sigChan
		cleanup()
	}()

	var lastChoice int
	for {
		// Display banner and menu together
		DisplayBanner()
		PrintMenuHeader("IoT Scout Menu")
		fmt.Println()

		menuItems := []string{
			"Capture live data from UART " + Yellow("(Currently under maintenance)"),
			"Analyze firmware",
			"Search for sensitive information",
			"Generate report",
			"Exit",
		}

		for i, item := range menuItems {
			if i == 0 {
				// Print the first item in yellow with a warning symbol
				fmt.Printf("   %s %s %s\n", Cyan("[1]"), item, Reset())
			} else {
				PrintMenuItem(i+1, item, i+1 == lastChoice)
			}
		}

		fmt.Println()
		PrintMenuFooter()

		// Add a warning message below the menu
		fmt.Printf("\n%s[!] Note: UART capture (Option 1) is currently under maintenance and not functional.%s\n", Yellow(""), Reset())

		// Get user choice
		fmt.Printf("\n%sEnter your choice (1-%d):%s ",
			Blue(""), len(menuItems), Reset())

		// Use the new GetUserInput function
		input := GetUserInput("")
		if input == "" {
			continue
		}

		choice, err := strconv.Atoi(input)
		if err != nil {
			PrintStatus("warning", "Please enter a valid number.")
			continue
		}

		lastChoice = choice
		fmt.Println()

		switch choice {
		case 1: // UART capture
			PrintSection("UART Capture")

			// Use the new GetUserInput function
			port := GetUserInput(fmt.Sprintf("%sEnter UART port (e.g., /dev/ttyUSB0):%s", Blue(""), Reset()))
			if port == "" {
				continue
			}

			serialManager = NewSerialManager(port)
			if err := serialManager.Connect(); err != nil {
				PrintStatus("error", fmt.Sprintf("Error connecting to UART: %v", err))
				continue
			}

			PrintStatus("success", fmt.Sprintf("Connected to %s", port))
			PrintStatus("info", "Waiting for device to boot (20 seconds)...")

			// Wait for boot without printing output
			serialManager.WaitForBoot()

			// Create process monitor
			processMonitor := NewProcessMonitor()
			processMonitor.SerialManager = serialManager

			// Display process list
			PrintSection("Running Processes")
			processMonitor.DisplayProcessList()

			// Save process list for report
			reportGenerator.ProcessList = processMonitor.GetProcessList()

			// Search for sensitive files
			PrintSection("Sensitive File Analysis")
			findings, err := firmwareAnalyzer.SearchSensitiveFiles()
			if err != nil {
				PrintStatus("error", fmt.Sprintf("Error searching for sensitive information: %v", err))
			} else {
				reportGenerator.SensitiveFindings = findings
				PrintStatus("success", "Sensitive information search complete")
			}

			// Disconnect from UART
			serialManager.Disconnect()
			PrintStatus("success", "Analysis complete")

		case 2: // Firmware analysis
			PrintSection("Firmware Analysis")
			path := GetFirmwarePath()
			if path == "" {
				continue
			}

			firmwareAnalyzer = NewLocalFirmwareAnalyzer(path)
			binaryAnalysis, iotBinaries, err := firmwareAnalyzer.AnalyzeFirmware()
			if err != nil {
				PrintStatus("error", fmt.Sprintf("Error analyzing firmware: %v", err))
				continue
			}

			reportGenerator.FirmwareAnalysis = binaryAnalysis
			reportGenerator.IotBinaries = iotBinaries
			PrintStatus("success", "Firmware analysis complete")

		case 3: // Sensitive information search
			PrintSection("Sensitive Information Search")
			if firmwareAnalyzer.FirmwarePath == "" {
				path := GetFirmwarePath()
				if path == "" {
					continue
				}
				firmwareAnalyzer = NewLocalFirmwareAnalyzer(path)
			}

			findings, err := firmwareAnalyzer.SearchSensitiveFiles()
			if err != nil {
				PrintStatus("error", fmt.Sprintf("Error searching for sensitive information: %v", err))
				continue
			}

			reportGenerator.SensitiveFindings = findings
			PrintStatus("success", "Sensitive information search complete")

		case 4: // Generate report
			PrintSection("Report Generation")
			if err := reportGenerator.SaveReport(); err != nil {
				PrintStatus("error", fmt.Sprintf("Error generating report: %v", err))
				continue
			}

		case 5: // Exit
			cleanup()

		default:
			PrintStatus("error", "Invalid choice. Please try again.")
		}
	}
}
