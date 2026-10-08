"""Native Tk/ttk interface to the same workflows used by the CLI.

Tk is imported only on launch so headless CLI/test environments need no display.
No user keys or documents are stored next to the application executable.
"""

from pathlib import Path

from securedoc.services.workflows import (
    initialize_ca,
    issue_identity,
    protect_file,
    recover_file,
    root_fingerprint,
)
from securedoc.utils.exceptions import SecureDocError


def launch(*, smoke: bool = False) -> None:
    import queue
    import threading
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise OSError(
            "A desktop display and working Tk installation are required."
        ) from exc
    root.title("SecureDoc Nepal | Document workspace")
    root.minsize(780, 660)
    root.geometry("940x760")
    root.configure(background="#f3f6fa")
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    style.configure("TFrame", background="#f3f6fa")
    style.configure("Card.TFrame", background="#ffffff")
    style.configure("TLabel", background="#f3f6fa", foreground="#233449")
    style.configure("Card.TLabel", background="#ffffff", foreground="#233449")
    style.configure("Title.TLabel", font=("TkDefaultFont", 20, "bold"))
    style.configure("Subtitle.TLabel", font=("TkDefaultFont", 10))
    style.configure("Heading.TLabel", font=("TkDefaultFont", 13, "bold"))
    style.configure("Accent.TButton", padding=(16, 9))
    style.configure("TButton", padding=(8, 6))
    style.configure("TEntry", padding=5)
    style.configure("TNotebook.Tab", padding=(17, 10))

    outer = ttk.Frame(root, padding=24)
    outer.pack(fill="both", expand=True)
    ttk.Label(outer, text="SecureDoc Nepal", style="Title.TLabel").pack(anchor="w")
    ttk.Label(
        outer,
        text=(
            "Local, signed and encrypted documents  •  "
            "Educational software, not audited"
        ),
        style="Subtitle.TLabel",
    ).pack(anchor="w", pady=(2, 16))

    trust_box = ttk.LabelFrame(
        outer, text="Trusted root · compare out of band", padding=14
    )
    trust_box.pack(fill="x", pady=(0, 14))
    trust_box.columnconfigure(1, weight=1)
    root_cert = tk.StringVar()
    root_pin = tk.StringVar()
    fields: dict[str, tk.StringVar] = {}
    passwords: list[tk.StringVar] = []

    def pick(value: tk.StringVar, *, save: bool = False, extension: str = "") -> None:
        options = {"initialdir": str(Path.home())}
        if extension:
            options["defaultextension"] = extension
        path = (
            filedialog.asksaveasfilename(parent=root, **options)
            if save
            else filedialog.askopenfilename(parent=root, **options)
        )
        if path:
            value.set(path)

    def row(
        panel: ttk.Frame,
        index: int,
        label: str,
        name: str,
        *,
        browse: str = "",
        password: bool = False,
    ) -> tk.StringVar:
        value = tk.StringVar()
        fields[name] = value
        if password:
            passwords.append(value)
        ttk.Label(panel, text=label, style="Card.TLabel").grid(
            row=index, column=0, sticky="w", padx=(0, 14), pady=7
        )
        entry = ttk.Entry(panel, textvariable=value, show="•" if password else "")
        entry.grid(row=index, column=1, sticky="ew", pady=7)
        if browse:
            ttk.Button(
                panel,
                text="Browse…",
                command=lambda: pick(
                    value,
                    save=browse == "save",
                    extension=".sdoc" if name == "seal_out" else "",
                ),
            ).grid(row=index, column=2, padx=(9, 0), pady=7)
        return value

    ttk.Label(trust_box, text="Root certificate").grid(
        row=0, column=0, sticky="w", padx=(0, 14)
    )
    ttk.Entry(trust_box, textvariable=root_cert).grid(row=0, column=1, sticky="ew")
    ttk.Button(trust_box, text="Browse…", command=lambda: pick(root_cert)).grid(
        row=0, column=2, padx=(9, 0)
    )
    ttk.Label(trust_box, text="Trusted SHA-256 fingerprint").grid(
        row=1, column=0, sticky="w", padx=(0, 14), pady=(9, 0)
    )
    ttk.Entry(trust_box, textvariable=root_pin).grid(
        row=1, column=1, sticky="ew", pady=(9, 0)
    )
    ttk.Button(
        trust_box,
        text="Show file fingerprint",
        command=lambda: show_fingerprint(),
    ).grid(row=1, column=2, padx=(9, 0), pady=(9, 0))
    ttk.Label(
        trust_box,
        text=(
            "The displayed fingerprint is NOT proof of trust. "
            "Confirm it through a separate channel."
        ),
    ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(12, 0))

    notebook = ttk.Notebook(outer)
    notebook.pack(fill="both", expand=True)

    def tab(title: str, heading: str, text: str) -> ttk.Frame:
        page = ttk.Frame(notebook, padding=20)
        notebook.add(page, text=title)
        ttk.Label(page, text=heading, style="Heading.TLabel").pack(anchor="w")
        ttk.Label(page, text=text, wraplength=750, justify="left").pack(
            anchor="w", pady=(6, 18)
        )
        card = ttk.Frame(page, style="Card.TFrame", padding=18)
        card.pack(fill="x")
        card.columnconfigure(1, weight=1)
        return card

    ca = tab(
        "1 · Create CA",
        "Create a local root",
        (
            "Keep your encrypted CA key and password safe. Share only the "
            "public certificate; verify its fingerprint out of band."
        ),
    )
    row(ca, 0, "New root key", "ca_key", browse="save")
    row(ca, 1, "New root certificate", "ca_cert", browse="save")
    row(ca, 2, "New key password", "ca_password", password=True)

    identity = tab(
        "2 · Issue identity",
        "Issue a user certificate",
        (
            "The name is self-declared by the CA operator. Issuance alone "
            "does not verify a real person's identity."
        ),
    )
    row(identity, 0, "Root private key", "issue_root_key", browse="open")
    row(identity, 1, "CA key password", "issue_root_password", password=True)
    row(identity, 2, "Common name", "issue_name")
    row(identity, 3, "Organization", "issue_org")
    row(identity, 4, "New user key", "issue_key", browse="save")
    row(identity, 5, "New user certificate", "issue_cert", browse="save")
    row(identity, 6, "New user password", "issue_password", password=True)

    seal = tab(
        "3 · Protect",
        "Sign and encrypt",
        (
            "Choose the signer's encrypted key and the recipient's public "
            "certificate. Each package has a new key. Maximum: 16 MiB."
        ),
    )
    row(seal, 0, "Document", "seal_in", browse="open")
    row(seal, 1, "New .sdoc output", "seal_out", browse="save")
    row(seal, 2, "Signer private key", "seal_key", browse="open")
    row(seal, 3, "Signer certificate", "seal_cert", browse="open")
    row(seal, 4, "Recipient certificate", "seal_recipient", browse="open")
    row(seal, 5, "Signer password", "seal_password", password=True)

    recover = tab(
        "4 · Open",
        "Verify and decrypt",
        (
            "Plaintext is saved only after root, certificate, signature and "
            "AES-GCM checks succeed. Choose a NEW output path."
        ),
    )
    row(recover, 0, ".sdoc package", "open_in", browse="open")
    row(recover, 1, "New output document", "open_out", browse="save")
    row(recover, 2, "Recipient private key", "open_key", browse="open")
    row(recover, 3, "Recipient certificate", "open_cert", browse="open")
    row(recover, 4, "Recipient password", "open_password", password=True)

    status = tk.StringVar(value="Ready · No secret is stored by the interface")
    ttk.Label(outer, textvariable=status, wraplength=840).pack(anchor="w", pady=(16, 0))
    finished: queue.Queue[tuple[bool, str]] = queue.Queue()
    buttons: list[ttk.Button] = []

    def show_fingerprint() -> None:
        try:
            value = root_fingerprint(Path(root_cert.get().strip()))
        except (SecureDocError, OSError) as exc:
            messagebox.showerror("Cannot read certificate", str(exc), parent=root)
        else:
            messagebox.showinfo(
                "Unverified fingerprint",
                (
                    f"{value}\n\nCompare this through an independent channel "
                    "before entering it as trusted."
                ),
                parent=root,
            )

    def run(action: str) -> None:
        values = {
            key: value.get().strip() if value not in passwords else value.get()
            for key, value in fields.items()
        }
        cert_path = root_cert.get().strip()
        pin = root_pin.get().strip()
        for secret in passwords:
            secret.set("")
        if any(
            not values[key]
            for key in {
                "ca": ("ca_key", "ca_cert", "ca_password"),
                "issue": (
                    "issue_root_key",
                    "issue_root_password",
                    "issue_name",
                    "issue_org",
                    "issue_key",
                    "issue_cert",
                    "issue_password",
                ),
                "seal": (
                    "seal_in",
                    "seal_out",
                    "seal_key",
                    "seal_cert",
                    "seal_recipient",
                    "seal_password",
                ),
                "open": (
                    "open_in",
                    "open_out",
                    "open_key",
                    "open_cert",
                    "open_password",
                ),
            }[action]
        ) or (action != "ca" and (not cert_path or not pin)):
            status.set("Complete all fields for this tab and the trusted root above.")
            return
        for button in buttons:
            button.state(["disabled"])
        status.set("Working… please wait; no existing output will be overwritten.")

        def task() -> None:
            try:
                if action == "ca":
                    pin_created = initialize_ca(
                        Path(values["ca_key"]),
                        Path(values["ca_cert"]),
                        values["ca_password"],
                    )
                    message = (
                        f"Root created. Verify and record fingerprint: {pin_created}"
                    )
                elif action == "issue":
                    issue_identity(
                        Path(values["issue_root_key"]),
                        Path(cert_path),
                        pin,
                        values["issue_root_password"],
                        Path(values["issue_key"]),
                        Path(values["issue_cert"]),
                        values["issue_password"],
                        name=values["issue_name"],
                        organization=values["issue_org"],
                    )
                    message = (
                        "User key and certificate created. "
                        "Identity not independently verified."
                    )
                elif action == "seal":
                    protect_file(
                        Path(values["seal_in"]),
                        Path(values["seal_out"]),
                        Path(values["seal_key"]),
                        Path(values["seal_cert"]),
                        Path(values["seal_recipient"]),
                        Path(cert_path),
                        pin,
                        values["seal_password"],
                    )
                    message = "Signed and encrypted package saved."
                else:
                    name = recover_file(
                        Path(values["open_in"]),
                        Path(values["open_out"]),
                        Path(values["open_key"]),
                        Path(values["open_cert"]),
                        Path(cert_path),
                        pin,
                        values["open_password"],
                    )
                    message = (
                        f"Verified, decrypted and saved. Package document name: {name}"
                    )
                finished.put((True, message))
            except (SecureDocError, OSError) as exc:
                finished.put((False, str(exc)))

        threading.Thread(target=task, daemon=True).start()

    for panel, action, caption in (
        (ca, "ca", "Create root"),
        (identity, "issue", "Issue certificate"),
        (seal, "seal", "Protect document"),
        (recover, "open", "Verify & decrypt"),
    ):
        button = ttk.Button(
            panel,
            text=caption,
            style="Accent.TButton",
            command=lambda selected=action: run(selected),
        )
        button.grid(row=8, column=1, sticky="e", pady=(14, 0))
        buttons.append(button)

    def process() -> None:
        try:
            success, message = finished.get_nowait()
        except queue.Empty:
            pass
        else:
            for button in buttons:
                button.state(["!disabled"])
            status.set(message)
            if success:
                messagebox.showinfo("Complete", message, parent=root)
            else:
                messagebox.showerror("Operation stopped", message, parent=root)
        root.after(100, process)

    root.after(100, process)
    if smoke:
        # Build verification starts the real window briefly, then exits.
        root.after(500, root.destroy)
    root.mainloop()
