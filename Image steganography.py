import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_message(message, key):
    cipher = Fernet(key)
    return cipher.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, key):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_message.encode()).decode()

def encode_message(image_path, message, output_path, key):
    encrypted_message = encrypt_message(message, key)
    encrypted_message += '\0'
    binary_message = ''.join(format(ord(char), '08b') for char in encrypted_message)
    
    img = cv2.imread(image_path)
    if img is None:
        print("Error: Image not found!")
        return
    
    data_index = 0
    data_length = len(binary_message)
    rows, cols, channels = img.shape
    
    for row in range(rows):
        for col in range(cols):
            for channel in range(channels):
                if data_index < data_length:
                    img[row, col, channel] = (img[row, col, channel] & ~1) | int(binary_message[data_index])
                    data_index += 1
                else:
                    break
    
    cv2.imwrite(output_path, img)
    print("Message encoded successfully!")

def decode_message(image_path, key):
    img = cv2.imread(image_path)
    if img is None:
        print("Error: Image not found!")
        return
    
    binary_message = ""
    rows, cols, channels = img.shape
    
    for row in range(rows):
        for col in range(cols):
            for channel in range(channels):
                binary_message += str(img[row, col, channel] & 1)
                if len(binary_message) % 8 == 0 and binary_message[-8:] == "00000000":
                    decrypted_message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message)-8, 8))
                    
                    try:
                        decrypted_message = decrypt_message(decrypted_message, key)
                    except:
                        print("Decryption failed! Incorrect key.")
                        return
                    
                    print("Decoded Message:", decrypted_message)
                    return
    
    print("No hidden message found.")

def browse_file():
    file_path = filedialog.askopenfilename()
    return file_path

def main_gui():
    root = tk.Tk()
    root.title("Image Steganography")
    root.geometry("400x300")
    
    def encode():
        img_path = browse_file()
        message = message_entry.get()
        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        key = generate_key()
        encode_message(img_path, message, output_path, key)
        messagebox.showinfo("Success", f"Message encoded successfully!\nSave this key: {key.decode()}")
    
    def decode():
        img_path = browse_file()
        key = key_entry.get().encode()
        decode_message(img_path, key)
    
    tk.Label(root, text="Enter message:").pack()
    message_entry = tk.Entry(root, width=50)
    message_entry.pack()
    
    tk.Button(root, text="Encode", command=encode).pack()
    
    tk.Label(root, text="Enter key for decoding:").pack()
    key_entry = tk.Entry(root, width=50)
    key_entry.pack()
    
    tk.Button(root, text="Decode", command=decode).pack()
    
    root.mainloop()

if __name__ == "__main__":
    main_gui()
