import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton, QLabel, QLineEdit, QFileDialog, QMessageBox, QProgressBar
from PyQt5.QtCore import Qt, QThread, pyqtSignal

def xor_cipher(data, key):
    key = bytearray(key * (len(data) // len(key)) + key[:len(data) % len(key)])
    return bytes(x ^ k for x, k in zip(data, key))

class EncodingThread(QThread):
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, input_file, key, output_file):
        super().__init__()
        self.input_file = input_file
        self.key = key
        self.output_file = output_file

    def run(self):
        try:
            key = self.key.encode('utf-8')
            with open(self.input_file, 'rb') as file:
                data = file.read()
            encoded_data = xor_cipher(data, key)
            with open(self.output_file, 'wb') as file:
                file.write(encoded_data)
            self.finished_signal.emit(True, f"File {self.input_file} has been encoded and saved as {self.output_file}")
        except Exception as e:
            self.finished_signal.emit(False, str(e))

class XORApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Swirtv Encoder/Decoder")
        self.setGeometry(100, 100, 400, 250)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()

        self.input_label = QLabel("Select a file:")
        layout.addWidget(self.input_label)

        self.input_line = QLineEdit()
        layout.addWidget(self.input_line)

        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_file)
        self.browse_button.setStyleSheet("background-color: #FF5733; color: black;")
        layout.addWidget(self.browse_button)

        self.key_label = QLabel("4-digit Key (4 characters):")
        layout.addWidget(self.key_label)

        self.key_line = QLineEdit()
        layout.addWidget(self.key_line)

        self.encode_button = QPushButton("Encode")
        self.encode_button.clicked.connect(self.encode_file)
        self.encode_button.setStyleSheet("background-color: #3498DB; color: white;")
        layout.addWidget(self.encode_button)

        self.decode_button = QPushButton("Decode")
        self.decode_button.clicked.connect(self.decode_file)
        self.decode_button.setStyleSheet("background-color: #E74C3C; color: white;")
        layout.addWidget(self.decode_button)

        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        self.central_widget.setLayout(layout)

        self.encoding_thread = EncodingThread(None, None, None)
        self.encoding_thread.finished_signal.connect(self.encoding_finished)

    def browse_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_name, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*);;Text Files (*.txt);;Binary Files (*)", options=options)
        if file_name:
            self.input_line.setText(file_name)

    def encode_file(self):
        input_file = self.input_line.text()
        key = self.key_line.text()

        if len(key) != 4:
            self.show_message("Error", "Key must be 4 characters long.")
            return

        output_file = input_file + '.swirtv'

        self.encoding_thread.input_file = input_file
        self.encoding_thread.key = key
        self.encoding_thread.output_file = output_file

        if not self.encoding_thread.isRunning():
            self.encoding_thread.start()

    def decode_file(self):
        input_file = self.input_line.text()
        key = self.key_line.text()

        if len(key) != 4:
            self.show_message("Error", "Key must be 4 characters long.")
            return

        output_file = input_file[:-6]

        self.encoding_thread.input_file = input_file
        self.encoding_thread.key = key
        self.encoding_thread.output_file = output_file

        if not self.encoding_thread.isRunning():
            self.encoding_thread.start()

    def encoding_finished(self, success, message):
        if success:
            self.show_message("Success", message)
        else:
            self.show_message("Error", message)
        self.progress_bar.setValue(0)

    def show_message(self, title, message):
        msg_box = QMessageBox()
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.exec()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = XORApp()
    window.show()
    sys.exit(app.exec_())
