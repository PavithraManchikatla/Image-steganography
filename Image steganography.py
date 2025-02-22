import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet

# Generate encryption key
def generate_key():
    return Fernet.generate_key()

# Encrypt message
def encrypt_message(message, key):
    return Fernet(key).encrypt(message.encode())

# Decrypt message
def decrypt_message(encrypted_message, key):
    return Fernet(key).decrypt(encrypted_message).decode()

# Encode message into image
def encode_message(image_path, message, output_path, key):
    key = key.encode()  # Convert key to bytes
    encrypted_message = encrypt_message(message, key) + b'\0'  # End marker
    binary_message = ''.join(format(byte, '08b') for byte in encrypted_message)

    img = cv2.imread(image_path)
    if img is None:
        messagebox.showerror("Error", "Image not found!")
        return

    data_index = 0
    data_length = len(binary_message)
    h, w, c = img.shape

    for i in range(h):
        for j in range(w):
            for k in range(c):
                if data_index < data_length:
                    img[i, j, k] = (img[i, j, k] & ~1) | int(binary_message[data_index])
                    data_index += 1
                else:
                    break

    if cv2.imwrite(output_path, img):
        messagebox.showinfo("Success", f"Message encoded!\nKey: {key.decode()}")
    else:
        messagebox.showerror("Error", "Failed to save encoded image!")

# Decode message from image
def decode_message(image_path, key):
    key = key.encode()
    img = cv2.imread(image_path)
    if img is None:
        messagebox.showerror("Error", "Image not found!")
        return

    binary_message = ""
    h, w, c = img.shape

    for i in range(h):
        for j in range(w):
            for k in range(c):
                binary_message += str(img[i, j, k] & 1)
    
    bytes_data = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    message_bytes = bytearray(int(b, 2) for b in bytes_data if int(b, 2) != 0)

    try:
        decrypted_message = decrypt_message(bytes(message_bytes), key)
        messagebox.showinfo("Decoded Message", decrypted_message)
    except:
        messagebox.showerror("Error", "Decryption failed! Incorrect key.")

# GUI for encoding and decoding
def main_gui():
    root = tk.Tk()
    root.title("Image Steganography")
    root.geometry("400x350")

    def encode():
        img_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if not img_path:
            messagebox.showerror("Error", "No image selected!")
            return

        message = message_entry.get()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if not output_path:
            messagebox.showerror("Error", "No output file selected!")
            return

        key = generate_key().decode()
        encode_message(img_path, message, output_path, key)

    def decode():
        img_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if not img_path:
            messagebox.showerror("Error", "No image selected!")
            return

        key = key_entry.get()
        if not key:
            messagebox.showerror("Error", "Key cannot be empty!")
            return

        decode_message(img_path, key)

    tk.Label(root, text="Enter message to hide:").pack()
    message_entry = tk.Entry(root, width=50)
    message_entry.pack()

    tk.Button(root, text="Encode Message", command=encode).pack()

    tk.Label(root, text="Enter key for decoding:").pack()
    key_entry = tk.Entry(root, width=50, show="*")
    key_entry.pack()

    tk.Button(root, text="Decode Message", command=decode).pack()

    root.mainloop()

if __name__ == "__main__":
    main_gui()
