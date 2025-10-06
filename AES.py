from tkinter import *
from tkinter import ttk, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import binascii

class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption Tool")
        self.root.geometry("800x750")
        self.root.configure(bg='#1e1e1e')
        
        # Center the window on screen
        self.center_window()
        
        # Custom colors
        self.bg_color = '#1e1e1e'
        self.fg_color = '#ffffff'
        self.entry_bg = '#2d2d2d'
        self.button_bg = '#3e3e3e'
        self.highlight_color = '#4e4e4e'
        self.accent_color = '#569cd6'
        
        self.setup_ui()
        
    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
    def setup_ui(self):
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # General styling
        style.configure('.', background=self.bg_color, foreground=self.fg_color)
        style.configure('TFrame', background=self.bg_color)
        style.configure('TLabel', background=self.bg_color, foreground=self.fg_color, font=('Segoe UI', 10))
        style.configure('TButton', background=self.button_bg, foreground=self.fg_color, 
                       font=('Segoe UI', 10), borderwidth=1)
        style.map('TButton', background=[('active', self.highlight_color)])
        style.configure('TEntry', fieldbackground=self.entry_bg, foreground=self.fg_color, 
                       insertcolor=self.fg_color, font=('Segoe UI', 10))
        style.configure('TCombobox', fieldbackground=self.entry_bg, foreground=self.fg_color)
        style.configure('TText', background=self.entry_bg, foreground=self.fg_color, 
                       font=('Consolas', 10), padx=5, pady=5)
        style.configure('TLabelframe', background=self.bg_color, foreground=self.accent_color)
        style.configure('TLabelframe.Label', background=self.bg_color, foreground=self.accent_color)
        
        # Main container
        mainframe = ttk.Frame(self.root, padding="20")
        mainframe.pack(expand=True, fill=BOTH)
        
        # Header
        header_frame = ttk.Frame(mainframe)
        header_frame.pack(fill=X, pady=(0, 15))
        
        ttk.Label(header_frame, text="AES Encryption Tool", 
                 font=('Segoe UI', 16, 'bold'), foreground=self.accent_color).pack()
        
        # Input Section
        input_frame = ttk.LabelFrame(mainframe, text=" Input Text ", padding="10")
        input_frame.pack(fill=X, pady=5)
        
        self.text_input = Text(input_frame, height=6, wrap=WORD, 
                             bg=self.entry_bg, fg=self.fg_color, 
                             insertbackground=self.fg_color, 
                             selectbackground=self.highlight_color)
        self.text_input.pack(fill=BOTH, expand=True)
        
        # Key Section
        key_frame = ttk.LabelFrame(mainframe, text=" Encryption Key ", padding="10")
        key_frame.pack(fill=X, pady=5)
        
        # Key size selection
        key_size_frame = ttk.Frame(key_frame)
        key_size_frame.pack(fill=X, pady=5)
        
        ttk.Label(key_size_frame, text="Key Size:").pack(side=LEFT, padx=(0, 10))
        self.key_size = StringVar(value="32")  # Default to 256-bit
        ttk.Combobox(key_size_frame, textvariable=self.key_size, 
                    values=["16", "24", "32"], width=5, state="readonly").pack(side=LEFT)
        ttk.Label(key_size_frame, text="bytes (128/192/256-bit)").pack(side=LEFT, padx=(5, 15))
        
        # Key input
        key_input_frame = ttk.Frame(key_frame)
        key_input_frame.pack(fill=X, pady=5)
        
        ttk.Label(key_input_frame, text="Secret Key (Base64):").pack(side=LEFT)
        self.key_input = ttk.Entry(key_input_frame)
        self.key_input.pack(side=LEFT, fill=X, expand=True, padx=(10, 5))
        
        ttk.Button(key_input_frame, text="Generate Key", command=self.generate_key, 
                  style='Accent.TButton', width=15).pack(side=LEFT)
        
        # IV Section
        iv_frame = ttk.LabelFrame(mainframe, text=" Initialization Vector (IV) ", padding="10")
        iv_frame.pack(fill=X, pady=5)
        
        ttk.Label(iv_frame, text="IV (Base64):").pack(side=LEFT)
        self.iv_input = ttk.Entry(iv_frame)
        self.iv_input.pack(side=LEFT, fill=X, expand=True, padx=(10, 5))
        
        ttk.Button(iv_frame, text="Generate IV", command=self.generate_iv, 
                  style='Accent.TButton', width=15).pack(side=LEFT)
        
        # Configuration Section
        config_frame = ttk.Frame(mainframe)
        config_frame.pack(fill=X, pady=10)
        
        # Mode selection
        mode_group = ttk.LabelFrame(config_frame, text=" Encryption Mode ", padding="10")
        mode_group.pack(side=LEFT)
        
        self.mode = StringVar(value="CBC")
        ttk.Radiobutton(mode_group, text="ECB", variable=self.mode, value="ECB",
                       command=self.toggle_iv_field).pack(anchor=W)
        ttk.Radiobutton(mode_group, text="CBC", variable=self.mode, value="CBC",
                       command=self.toggle_iv_field).pack(anchor=W)
        
        # Output format
        format_group = ttk.LabelFrame(config_frame, text=" Output Format ", padding="10")
        format_group.pack(side=LEFT, padx=10)
        
        self.output_format = StringVar(value="Base64")
        ttk.Radiobutton(format_group, text="Base64", variable=self.output_format, 
                       value="Base64").pack(anchor=W)
        ttk.Radiobutton(format_group, text="Hexadecimal", variable=self.output_format, 
                       value="Hexadecimal").pack(anchor=W)
        
        # Action Buttons
        button_frame = ttk.Frame(mainframe)
        button_frame.pack(fill=X, pady=10)
        
        ttk.Button(button_frame, text="Encrypt", command=self.encrypt, 
                  style='Accent.TButton', width=15).pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt, 
                  style='Accent.TButton', width=15).pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text="Clear All", command=self.clear_all, 
                  width=15).pack(side=LEFT, padx=5)
        
        # Output Section
        output_frame = ttk.LabelFrame(mainframe, text=" Output ", padding="10")
        output_frame.pack(fill=BOTH, expand=True, pady=5)
        
        self.result_output = Text(output_frame, height=6, wrap=WORD, 
                                bg=self.entry_bg, fg=self.fg_color, 
                                insertbackground=self.fg_color, 
                                selectbackground=self.highlight_color)
        self.result_output.pack(fill=BOTH, expand=True)
        
        # Status bar
        self.status = StringVar(value="Ready")
        status_bar = ttk.Label(mainframe, textvariable=self.status, 
                             foreground='#a0a0a0', font=('Segoe UI', 9))
        status_bar.pack(fill=X, pady=(5, 0))
        
        # Configure the accent button style
        style.configure('Accent.TButton', background=self.accent_color, 
                       foreground='black', font=('Segoe UI', 10, 'bold'))
        style.map('Accent.TButton', 
                 background=[('active', '#79b6e3')])
        
        # Initialize IV field state
        self.toggle_iv_field()
        
    def toggle_iv_field(self):
        if self.mode.get() == "ECB":
            self.iv_input.config(state=DISABLED)
        else:
            self.iv_input.config(state=NORMAL)
    
    def generate_key(self):
        key_size = int(self.key_size.get())
        key = get_random_bytes(key_size)
        self.key_input.delete(0, END)
        self.key_input.insert(0, base64.b64encode(key).decode('utf-8'))
        self.status.set(f"Generated new {key_size*8}-bit key")
        
    def generate_iv(self):
        iv = get_random_bytes(16)  # AES block size is 16 bytes
        self.iv_input.delete(0, END)
        self.iv_input.insert(0, base64.b64encode(iv).decode('utf-8'))
        self.status.set("Generated new IV")
        
    def clear_all(self):
        self.text_input.delete(1.0, END)
        self.key_input.delete(0, END)
        self.iv_input.delete(0, END)
        self.result_output.delete(1.0, END)
        self.status.set("Cleared all fields")
        
    def encrypt(self):
        try:
            plaintext = self.text_input.get(1.0, END).strip()
            if not plaintext:
                messagebox.showerror("Error", "Please enter text to encrypt")
                return
                
            key = self.key_input.get().strip()
            if not key:
                messagebox.showerror("Error", "Please enter a secret key")
                return
                
            try:
                key = base64.b64decode(key)
            except:
                messagebox.showerror("Error", "Invalid key format. Please use Base64")
                return
                
            if len(key) not in [16, 24, 32]:
                messagebox.showerror("Error", "Key must be 16, 24, or 32 bytes (128, 192, or 256-bit)")
                return
                
            mode = self.mode.get()
            output_format = self.output_format.get()
            
            if mode == "CBC":
                iv = self.iv_input.get().strip()
                if not iv:
                    messagebox.showerror("Error", "Please provide an IV for CBC mode")
                    return
                try:
                    iv = base64.b64decode(iv)
                    if len(iv) != 16:
                        messagebox.showerror("Error", "IV must be exactly 16 bytes (128 bits)")
                        return
                except:
                    messagebox.showerror("Error", "Invalid IV format. Please use Base64")
                    return
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            else:
                cipher = AES.new(key, AES.MODE_ECB)
                
            padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            
            if output_format == "Base64":
                if mode == "CBC":
                    result = base64.b64encode(iv + ciphertext).decode('utf-8')
                else:
                    result = base64.b64encode(ciphertext).decode('utf-8')
            else:  # Hexadecimal
                if mode == "CBC":
                    result = binascii.hexlify(iv + ciphertext).decode('utf-8')
                else:
                    result = binascii.hexlify(ciphertext).decode('utf-8')
                
            self.result_output.delete(1.0, END)
            self.result_output.insert(1.0, result)
            self.status.set("Encryption successful")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.status.set("Encryption failed")
            
    def decrypt(self):
        try:
            ciphertext = self.text_input.get(1.0, END).strip()
            if not ciphertext:
                messagebox.showerror("Error", "Please enter ciphertext to decrypt")
                return
                
            key = self.key_input.get().strip()
            if not key:
                messagebox.showerror("Error", "Please enter a secret key")
                return
                
            try:
                key = base64.b64decode(key)
            except:
                messagebox.showerror("Error", "Invalid key format. Please use Base64")
                return
                
            if len(key) not in [16, 24, 32]:
                messagebox.showerror("Error", "Key must be 16, 24, or 32 bytes (128, 192, or 256-bit)")
                return
                
            # Try both formats (Base64 and Hexadecimal)
            ciphertext_bytes = None
            formats_tried = []
            
            # First try Base64
            try:
                ciphertext_bytes = base64.b64decode(ciphertext)
                formats_tried.append("Base64")
            except:
                pass
                
            # If Base64 failed, try Hexadecimal
            if ciphertext_bytes is None:
                try:
                    ciphertext_bytes = bytes.fromhex(ciphertext)
                    formats_tried.append("Hexadecimal")
                except:
                    pass
                    
            if ciphertext_bytes is None:
                messagebox.showerror("Error", "Invalid ciphertext format - not Base64 or Hexadecimal")
                self.status.set("Decryption failed (invalid format)")
                return
                
            # Try both ECB and CBC modes automatically
            plaintext = None
            modes_tried = []
            
            # First try CBC mode (most common)
            if len(ciphertext_bytes) >= 16:
                try:
                    iv = ciphertext_bytes[:16]
                    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                    padded_plaintext = cipher.decrypt(ciphertext_bytes[16:])
                    plaintext = unpad(padded_plaintext, AES.block_size).decode('utf-8')
                    modes_tried.append("CBC")
                except Exception as e:
                    pass
            
            # If CBC failed, try ECB
            if plaintext is None:
                try:
                    cipher = AES.new(key, AES.MODE_ECB)
                    padded_plaintext = cipher.decrypt(ciphertext_bytes)
                    plaintext = unpad(padded_plaintext, AES.block_size).decode('utf-8')
                    modes_tried.append("ECB")
                except Exception as e:
                    pass
            
            if plaintext is None:
                messagebox.showerror("Error", "Decryption failed - tried CBC and ECB modes")
                self.status.set(f"Decryption failed (tried {', '.join(modes_tried)} with {formats_tried[-1]})")
                return
                
            self.result_output.delete(1.0, END)
            self.result_output.insert(1.0, plaintext)
            self.status.set(f"Decryption successful (used {modes_tried[-1]} mode with {formats_tried[-1]} format)")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.status.set("Decryption failed")

if __name__ == "__main__":
    root = Tk()
    app = AESApp(root)
    root.mainloop()