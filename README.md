# LAN Clipboard

A secure clipboard sharing application that allows text and file sharing between devices on the same local network.

## Features

- 🔄 Real-time text and file sharing across LAN
- 🔒 Encrypted data transmission using Fernet encryption
- 📱 Automatic device discovery on the local network
- 📋 Clipboard integration (copy/paste functionality)
- 📂 File sharing capabilities
- 📜 History tracking of shared content
- ⚙️ Customizable settings
- 🎨 Modern and user-friendly interface

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/khalil-debug/LANClipboard.git
   cd LANClipboard
   ```

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:

   ```bash
   python lan_clipboard.py
   ```

   or run the EXE file present in dist folder.

2. The application will automatically:
   - Scan for other devices on the network
   - Start listening for incoming connections
   - Enable the discovery service

3. To share content:
   - Select a target device from the dropdown
   - Type or paste text into the text area
   - Click "Share" to send the content
   - Or use "Share File" to send files

## Security

- All data transmission is encrypted using Fernet symmetric encryption
- You can set custom encryption keys or generate new ones
- Keys are never transmitted over the network

## Requirements

- Python 3.6+
- Local network connection
- Required packages (see requirements.txt):
  - cryptography
  - pyperclip

## Configuration

The application allows customization of:
- Maximum history items
- Auto-clear after sending
- Encryption keys
- Network settings

## Troubleshooting

Common issues:
1. **Device not found**: Ensure both devices are on the same network
2. **Connection failed**: Check firewall settings
3. **Encryption errors**: Verify both devices use the same encryption key

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with Python and Tkinter
- Uses Fernet encryption from the cryptography package
- Clipboard integration via pyperclip

## Contact

For support or queries, please open an issue in the GitHub repository.
