#stgno 2

import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from PIL import Image
# Create the main application window
app = tk.Tk()
app.title("Steganography App")
regex = {}

def open_reg_window():
    register_window = tk.Toplevel(app)
    register_window.title("New User Login")

    def registration():
        username = username_entry.get()
        password = password_entry.get()

        if username and password not in regex:
            regex[username] = password
            messagebox.showinfo("Login Successful")
            register_window.destroy()
            # how to move to next window automatically when registration is done???
            return regex
        elif username in regex:
            messagebox.showinfo("Username not available ")
        elif password in regex:
            messagebox.showinfo("Password not available ")

    register_label = tk.Label(register_window, text="Enter new Username and Password:")
    register_label.pack()
    username_label = tk.Label(register_window, text="Username:")
    username_label.pack()
    username_entry = tk.Entry(register_window)
    username_entry.pack()
    password_label = tk.Label(register_window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(register_window, show="*")
    password_entry.pack()
    register_button = tk.Button(register_window, text="Register", command=registration)
    register_button.pack()


def open_auth_window():
    auth_window = tk.Toplevel(app)
    auth_window.title("Authentication")

    auth_label = tk.Label(auth_window, text="Enter Username and Password:")
    auth_label.pack()
    username_label = tk.Label(auth_window, text="Username:")
    username_label.pack()
    username_entry = tk.Entry(auth_window)
    username_entry.pack()
    password_label = tk.Label(auth_window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(auth_window, show="*")
    password_entry.pack()

    def authenticate():
        username = username_entry.get()
        password = password_entry.get()
        if username in regex and regex[username] == password:
            messagebox.showinfo("Access granted")
            app.attributes('-disabled', False)
            encode_button.config(state=tk.NORMAL)
            decode_button.config(state=tk.NORMAL)
            auth_window.destroy()
        else:
            messagebox.showerror("Authentication Failed", "Invalid username or password.")
            #app.attributes('-disabled', True)
            encode_button.config(state=tk.DISABLED)
            decode_button.config(state=tk.DISABLED)

    authenticate_button = tk.Button(auth_window, text="Authenticate",
                                    command=authenticate)
    authenticate_button.pack()



# Function to encode a message into an image
def encode_image():
    # Get the selected image file and message from the user
    image_path = filedialog.askopenfilename(title="Select an image file")
    message = message_entry.get()

    if not image_path:
        messagebox.showerror("Error", "Please select an image file.")
        return

    # Open the image
    img = Image.open(image_path)
    width, height = img.size

    eom_marker = "111111110"

    # Convert message to binary
    binary_message = ''.join(format(ord(char), '08b') for char in message)

    binary_message += eom_marker

    # Ensure the message fits in the image
    if len(message) > (width * height * 3) // 8:
        messagebox.showerror("Error", "Message is too long to fit in the image.")
        return

    index = 0

    # Loop through image pixels and encode the message
    for y in range(height):
        for x in range(width):
            pixel = list(img.getpixel((x, y)))

            for color_channel in range(3):
                if index < len(binary_message):
                    pixel[color_channel] = int(bin(pixel[color_channel])[2:9] + binary_message[index], 2)
                    index += 1

            img.putpixel((x, y), tuple(pixel))

    # Save the encoded image
    encoded_image_path = filedialog.asksaveasfilename(title="Save the encoded image", defaultextension=".png")
    img.save(encoded_image_path)
    messagebox.showinfo("Success", "Message encoded and saved successfully.")

# Function to decode a message from an encoded image
def decode_image():
    # Get the selected encoded image file
    encoded_image_path = filedialog.askopenfilename(title="Select an encoded image file")

    if not encoded_image_path:
        messagebox.showerror("Error", "Please select an encoded image file.")
        return

    # Open the encoded image
    img = Image.open(encoded_image_path)

    binary_message = ""

    for pixel in img.getdata():
        for color_channel in range(3):
            binary_message += bin(pixel[color_channel])[-1]

    # Define the end-of-message marker
    eom_marker = "111111110"

    # Find the end-of-message marker index
    eom_marker_index = binary_message.find(eom_marker)

    if eom_marker_index != -1:
        binary_message = binary_message[:eom_marker_index]  # Truncate the binary message

    message = ""
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i + 8]
        message += chr(int(byte, 2))

    messagebox.showinfo("Decoded Message", f"Decoded message:\n{message}")

# ... (previous code)

# Create and set up the authentication window
button = tk.Button(app, text="Sign-Up", command=open_reg_window)
button.pack()


button = tk.Button(app, text="Log-in", command=open_auth_window)
button.pack()



# Create and set up the main application window
message_label = tk.Label(app, text="Enter a message:")
message_label.pack()

message_entry = tk.Entry(app)
message_entry.pack()

encode_button = tk.Button(app, text="Encode Message", command=encode_image, state=tk.DISABLED)
encode_button.pack()

decode_button = tk.Button(app, text="Decode Message", command=decode_image, state=tk.DISABLED)
decode_button.pack()

app.mainloop()