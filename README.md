# TorrentGuard
 P2P BitTorrent Client with VPN/TLS

This is a project that implements a simplified BitTorrent-like peer-to-peer (P2P) file-sharing client in Python.  
It features a central tracker for peer discovery, parallel chunk downloading for efficiency, a Tit-for-Tat choking algorithm for fair uploading, and secure peer-to-peer communication using a TLS layer.

---

## 🚀 Features

- **Tracker-Based Peer Discovery**  
  A central `tracker.py` server manages the list of available files and the peers that have them.

- **P2P File Sharing**  
  Peers can download files directly from other peers without relying on the tracker for data transfer.

- **Parallel Chunk Downloading**  
  Downloads are divided into chunks and fetched from multiple peers simultaneously to maximize speed.

- **Secure Communication (TLS)**  
  The `vpn.py` module handles the creation of self-signed certificates and wraps peer-to-peer sockets in a TLS layer for encrypted communication.

- **Tit-for-Tat Choking Algorithm**  
  Ensures fairness by prioritizing uploads to peers providing higher download rates. Includes an "optimistic unchoke" to periodically test for better peers.

- **Command-Line Interface (CLI)**  
  The interactive `peer.py` script allows users to share files, list network files, and initiate downloads.

- **(Optional) Web Interface**  
  A `streamlit_app.py` provides a graphical interface to interact with the P2P network.

---

## 📁 Project Structure

```

.
├── tracker.py           # Central tracker server
├── peer.py              # Main P2P client with CLI
├── vpn.py               # TLS certificate generation and SSL context
├── streamlit_app.py     # (Optional) Web interface for the client
├── requirements.txt     # Python dependencies
├── shared_files/        # Directory of files to share
├── downloads/           # Directory for completed downloads
├── certs/               # Stores generated TLS certificates
└── logs/                # Peer and tracker log files

````

---

## ⚙️ Setup and Installation

### Prerequisites
- Python **3.8+**
- `pip` for installing dependencies

### Installation Steps

1. **Clone the Repository**
    ```bash
    git clone https://github.com/saimayithri/Secure_Bittorent
    cd Secure_Bittorent
    ```

2. **Create a Virtual Environment (Recommended)**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

---

## 🖥️ How to Run

The system requires **one tracker** and **at least two peers** to function.

### 1. Start the Tracker
Run the tracker server:
```bash
python tracker.py
````

It will start listening for peer connections (default: `localhost:5000`).

### 2. Start a Peer

Open a new terminal for each peer:

```bash
python peer.py
```

* When prompted, enter the tracker’s host and port (press **Enter** for defaults: `localhost:5000`).
* The peer automatically scans the `shared_files` directory and registers available files with the tracker.

### 3. Run Multiple Peers

Repeat Step 2 in separate terminals to simulate multiple peers.

---

## ⏱️ CLI Usage

Once `peer.py` is running, an interactive menu will appear:

* **Share Files**
  Add files to the `shared_files` directory and select the "Share" option to rescan and register them.

* **List Available Files**
  Fetches a list of all files shared by all peers.

* **Download File**
  Choose a file number to start downloading. The file will be saved to the `downloads` directory.

* **Show Progress**
  Displays real-time download status and peer contribution details.

* **Quit**
  Gracefully shuts down the peer and unregisters it from the tracker.

---

## 🔒 Security Note

This project uses **self-signed certificates** for demonstration purposes.
While it provides **encryption**, it does **not protect against man-in-the-middle (MITM)** attacks.

> ⚠️ **Do not use this for sharing sensitive or personal data over public networks.**

---

## 🧰 Technologies Used

* Python (Socket Programming, Threading, TLS/SSL)
* Streamlit (Optional GUI)
* OpenSSL (via Python’s `ssl` module)
* Custom implementation of Tit-for-Tat peer management

---

## 📜 License

This project is developed for **educational purposes** as part of a university course.
Feel free to modify and extend it for research or academic use.

---

**Author:** T. Sai Mayithri
**Domain:** Computer Networks & Security
**Language:** Python 3.8+

```

