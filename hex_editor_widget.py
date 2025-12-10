import sys
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLabel, QPushButton,
    QFileDialog
)
from PyQt6.QtGui import QFont

class HexEditorWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # File operations
        file_layout = QHBoxLayout()
        open_btn = QPushButton("Open File")
        open_btn.clicked.connect(self.open_file)
        file_layout.addWidget(open_btn)
        
        save_btn = QPushButton("Save File")
        save_btn.clicked.connect(self.save_file)
        file_layout.addWidget(save_btn)
        
        layout.addLayout(file_layout)

        # Main editor layout
        editor_layout = QHBoxLayout()

        # Hex view
        hex_frame = QWidget()
        hex_layout = QVBoxLayout(hex_frame)
        hex_label = QLabel("Hex View")
        self.hex_view = QTextEdit()
        self.hex_view.setFont(QFont("Consolas", 12))
        self.hex_view.textChanged.connect(self.hex_to_ascii)
        hex_layout.addWidget(hex_label)
        hex_layout.addWidget(self.hex_view)
        
        # ASCII view
        ascii_frame = QWidget()
        ascii_layout = QVBoxLayout(ascii_frame)
        ascii_label = QLabel("ASCII View")
        self.ascii_view = QTextEdit()
        self.ascii_view.setFont(QFont("Consolas", 12))
        self.ascii_view.textChanged.connect(self.ascii_to_hex)
        ascii_layout.addWidget(ascii_label)
        ascii_layout.addWidget(self.ascii_view)

        editor_layout.addWidget(hex_frame)
        editor_layout.addWidget(ascii_frame)
        
        layout.addLayout(editor_layout)
        
        self._block_signals = False

    def ascii_to_hex(self):
        if self._block_signals:
            return
        self._block_signals = True
        try:
            text = self.ascii_view.toPlainText()
            hex_represenation = text.encode('utf-8', 'replace').hex(' ')
            self.hex_view.setPlainText(hex_represenation)
        finally:
            self._block_signals = False

    def hex_to_ascii(self):
        if self._block_signals:
            return
        self._block_signals = True
        try:
            hex_text = self.hex_view.toPlainText().replace(" ", "").replace("\n", "")
            if len(hex_text) % 2 != 0:
                hex_text = hex_text[:-1] # Ensure even length
            
            try:
                byte_data = bytes.fromhex(hex_text)
                text = byte_data.decode('utf-8', 'replace')
                self.ascii_view.setPlainText(text)
            except ValueError:
                # Ignore invalid hex characters for a smoother experience
                pass
        finally:
            self._block_signals = False

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Binary File", "", "All Files (*)")
        if path:
            try:
                with open(path, 'rb') as f:
                    content = f.read()
                
                self._block_signals = True
                self.hex_view.setPlainText(content.hex(' '))
                self.ascii_view.setPlainText(content.decode('utf-8', 'replace'))
                self._block_signals = False
            except Exception as e:
                print(f"Error opening file: {e}")

    def save_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Binary File", "", "All Files (*)")
        if path:
            try:
                # Use the hex view as the source of truth
                hex_text = self.hex_view.toPlainText().replace(" ", "").replace("\n", "")
                byte_data = bytes.fromhex(hex_text)
                with open(path, 'wb') as f:
                    f.write(byte_data)
            except Exception as e:
                print(f"Error saving file: {e}")