# LAN Clipboard

**Struggling to share passwords or sensitive information securely across your local network?** Sending plain text via chat or email within the same network is risky. LAN Clipboard solves this problem by providing a secure, easy-to-use desktop application built with Python. Share text and files confidently between your devices, knowing your data is encrypted end-to-end using state-of-the-art Fernet encryption.

LAN Clipboard allows seamless and secure sharing of text and files between multiple devices connected to the same Local Area Network (LAN). No more emailing yourself or using unsecured methods!

## Key Features

-   **🔒 Secure Sharing**: All data is encrypted using Fernet symmetric encryption before transmission. Set your own unique key or generate one easily.
-   **🔄 Real-time Transfer**: Instantly share text snippets or entire files across your LAN.
-   **📱 Automatic Discovery**: Automatically discovers other LAN Clipboard instances on your network using Zeroconf. No need to manually enter IP addresses.
-   **📂 File Sharing**: Transfer files of any type with a simple click, with progress indication.
-   **📋 Clipboard Integration**: Quickly copy content to your system clipboard or paste from it into the application.
-   **📜 History**: Access recently shared text snippets via the history dropdown.
-   **🎨 Modern UI**: Clean, intuitive interface built with Tkinter and the `sv-ttk` theme.
-   **⚙️ Cross-Platform**: Built with Python, aiming for cross-platform compatibility (currently packaged for Windows).

## Installation

You can run LAN Clipboard in two ways:

**1. Using Python (Recommended for non-Windows or developers)**

   - **Prerequisites**: Python 3.6+ and `pip`.
   - **Clone the repository**:
     ```bash
     git clone https://github.com/khalil-debug/LANClipboard.git
     cd LANClipboard
     ```
   - **Install dependencies**:
     ```bash
     pip install -r requirements.txt
     ```
   - **Run the application**:
     ```bash
     python lan_clipboard.py
     ```

**2. Using the Windows Executable**

   - Download the latest release from the [Releases](https://github.com/khalil-debug/LANClipboard/releases) page (or find it in the `dist` folder if you built it yourself).
   - Unzip the package if necessary.
   - Run `LANClipboard.exe`. No installation is required.

## How to Use

1.  **Launch** the LAN Clipboard application on two or more devices on the same network.
2.  **⚠️ IMPORTANT: Set a unique encryption key!**
    *   On first launch, you'll be prompted to change the default key.
    *   Type your own keyword/passphrase and click `Set Key`.
    *   Alternatively, click `Generate Key`. Then, click `Share Key` to send the generated key as text to another device.
    *   **Both devices MUST use the exact same encryption key** to communicate. The recipient must copy the received key (if shared) and use `Set Key`.
3.  **Select Device**: Choose the target device from the `Available Devices` dropdown. The status indicator will show if a connection is possible (● Green: Connected, ● Red: Not Connected, ● Blue: Local PC).
4.  **Share Text**: Type or paste text into the `Content` area and click `Share Text`.
5.  **Share File**: Click `Share File`, select the file you want to send, and the transfer will begin. The recipient will be prompted to save the file.
6.  **Receive**: Incoming text will appear in the `Content` area. You'll be prompted to choose a save location for incoming files.

## Security Details

-   Data is encrypted using `cryptography.fernet`, a standard symmetric encryption library.
-   Your encryption key (whether set or generated) is **never** transmitted automatically. It must be shared manually (e.g., using the 'Share Key' feature or verbally) and set on the receiving device.
-   Always set a unique key different from the default for secure communication.

## Requirements (for running with Python)

-   Python 3.6+
-   Local network connection (Wi-Fi or Ethernet)
-   Required Python packages (installed via `requirements.txt`):
    -   `cryptography`
    -   `pyperclip`
    -   `sv_ttk`
    -   `zeroconf`

## Troubleshooting

-   **Device not found**: Ensure devices are on the same Wi-Fi/LAN. Check if firewalls (Windows Defender, etc.) are blocking Python or the application, especially on private/public network profiles. Allow the application through the firewall if prompted.
-   **Connection failed**: Verify firewall settings on both devices.
-   **Decryption errors**: Ensure **exactly** the same encryption key keyword is set on both devices. Regenerate and share a key if unsure.

## Contributing

Contributions are welcome! Please follow these steps:

1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/YourFeature`).
3.  Commit your changes (`git commit -m 'Add YourFeature'`).
4.  Push to the branch (`git push origin feature/YourFeature`).
5.  Open a Pull Request.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgments

-   Built with Python and Tkinter.
-   Uses `cryptography` for encryption.
-   Uses `pyperclip` for clipboard access.
-   Uses `zeroconf` for network discovery.
-   Uses `sv-ttk` for the UI theme.

## Contact

For issues, questions, or suggestions, please open an issue in the GitHub repository.
