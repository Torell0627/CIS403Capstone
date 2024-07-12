# encryptDecrypt.py
# DEFINE FUNCTION encode(key, msg)
#   INITIALIZE empty list enc
#   FOR each character in msg
#       COMPUTE encoded character using key
#       APPEND encoded character to enc
#   RETURN base64 encoded string of joined enc
# DEFINE FUNCTION decode(key, code)
#   INITIALIZE empty list dec
#   DECODE code using base64
#   FOR each character in decoded string
#       COMPUTE decoded character using key
#       APPEND decoded character to dec
#   RETURN joined dec
# DEFINE FUNCTION result(event=None)
#   GET msg, key, mode from entry fields
#   IF mode is encode
#       SET output to encoded message
#   ELSE IF mode is decode
#       SET output to decoded message
#   ELSE
#       SHOW error message for invalid mode
# DEFINE FUNCTION reset()
#   CLEAR Message, key, mode, Output
# DEFINE FUNCTION main()
#   CREATE main window
#   INITIALIZE Message, key, mode, Output as StringVar or IntVar
#   CREATE and PACK heading frame and label
#   CREATE and PACK entry fields and labels for message and key
#   CREATE and PACK radio buttons for encrypt and decrypt modes
#   CREATE and PACK entry field and label for results
#   CREATE and PACK buttons for Show Message, Reset, Exit
#   ENTER mainloop() to keep the application running

from tkinter import *
import base64
from tkinter import messagebox
import tkinter.font as font


# Encoding Function
def encode(key, msg):
    enc = []
    for i in range(len(msg)):
        list_key = key[i % len(key)]
        list_enc = chr((ord(msg[i]) + ord(list_key)) % 256)
        enc.append(list_enc)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


# Decoding Function
def decode(key, code):
    dec = []
    enc = base64.urlsafe_b64decode(code).decode()
    for i in range(len(enc)):
        list_key = key[i % len(key)]
        list_dec = chr((256 + ord(enc[i]) - ord(list_key)) % 256)
        dec.append(list_dec)
    return "".join(dec)


# Function that executes on clicking Show Message function
def result(event=None):
    msg = Message.get()
    k = key.get()
    i = mode.get()
    if i == 1:
        Output.set(encode(k, msg))
    elif i == 2:
        Output.set(decode(k, msg))
    else:
        messagebox.showinfo('ProjectDecode', 'Please Choose either Encryption or Decryption. Try again.')


# Function that executes on clicking Reset function
def reset():
    Message.set("")
    key.set("")
    mode.set(0)
    Output.set("")


def main():
    global Message, key, mode, Output  # Make these variables global to access in other functions
    wn = Tk()
    wn.geometry("500x500")
    wn.configure(bg='gray63')
    wn.title("Encrypt and Decrypt your Messages!")

    Message = StringVar()
    key = StringVar()
    mode = IntVar()
    Output = StringVar()

    heading_frame1 = Frame(wn, bg="gray91", bd=5)
    heading_frame1.place(relx=0.2, rely=0.1, relwidth=0.7, relheight=0.16)

    heading_label = Label(heading_frame1, text=" Welcome to my Encryption and \nDecryption tool.", fg='black',
                          font=('Georgia', 13, 'bold'), bd=2, relief='solid')
    heading_label.place(relx=0, rely=0, relwidth=1, relheight=1)

    label1 = Label(wn, text='Enter a Message:', font=('Georgia', 10), bd=2, relief='solid')
    label1.place(x=10, y=150)

    msg = Entry(wn, textvariable=Message, width=35, font=('calibre', 10, 'normal'))
    msg.place(x=200, y=150)

    label2 = Label(wn, text='Enter a key:', font=('Georgia', 10), bd=2, relief='solid')
    label2.place(x=10, y=200)

    inp_key = Entry(wn, textvariable=key, width=35, font=('calibre', 10, 'normal'))
    inp_key.place(x=200, y=200)

    frame3 = Frame(wn, bg='gray63')
    frame3.place(x=10, y=250)

    label3 = Label(frame3, text='Select one of encrypt or decrypt', font=('Georgia', 10), bd=2, relief='solid')
    label3.pack(side=LEFT)

    bold_font = font.Font(family='Georgia', size=10, weight='bold')

    Radiobutton(frame3, text='Encrypt', variable=mode, value=1, font=bold_font).pack(side=LEFT, padx=10)
    Radiobutton(frame3, text='Decrypt', variable=mode, value=2, font=bold_font).pack(side=LEFT, padx=10)

    label4 = Label(wn, text='Results:', font=('Georgia', 10), bd=2, relief='solid')
    label4.place(x=10, y=350)

    res = Entry(wn, textvariable=Output, width=35, font=('calibre', 10, 'normal'))
    res.place(x=200, y=350)

    show_btn = Button(wn, text="Show Message", bg='lawn green', fg='black', width=15, height=1, command=result)
    show_btn['font'] = font.Font(size=12)
    show_btn.place(x=180, y=400)

    reset_btn = Button(wn, text='Reset', bg='dodger blue', fg='black', width=15, height=1, command=reset)
    reset_btn['font'] = font.Font(size=12)
    reset_btn.place(x=15, y=400)

    quit_btn = Button(wn, text='Exit', bg='brown1', fg='black', width=15, height=1, command=wn.destroy)
    quit_btn['font'] = font.Font(size=12)
    quit_btn.place(x=345, y=400)

    wn.bind('<Return>', result)  # Bind Enter key to the result function

    wn.mainloop()


if __name__ == "__main__":
    main()
