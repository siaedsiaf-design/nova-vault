"""
Nova Vault — Android Edition
Kivy + KivyMD UI (Arabic Fusha + Noto Naskh Arabic font)
"""

import os, sys, base64, secrets, string, sqlite3, threading, hashlib, hmac, json
from pathlib import Path
from datetime import datetime, timedelta

os.environ["KIVY_NO_ENV_CONFIG"] = "1"

from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.widget import Widget
from kivy.core.clipboard import Clipboard
from kivy.core.text import LabelBase
from kivy.resources import resource_add_path
from kivy.metrics import dp, sp
from kivy.graphics import Color, RoundedRectangle, Rectangle
from kivy.clock import Clock
from kivy.utils import platform
from kivy.core.window import Window
from kivy.lang import Builder

# ── KivyMD ────────────────────────────────────────────────────────────────────
try:
    from kivymd.app import MDApp
    USE_MD = True
except ImportError:
    USE_MD = False
    MDApp = App

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from argon2.low_level import hash_secret_raw, Type
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ── Arabic ────────────────────────────────────────────────────────────────────
try:
    import arabic_reshaper
    from bidi.algorithm import get_display
    ARABIC_OK = True
except ImportError:
    ARABIC_OK = False

# ── Arabic font ───────────────────────────────────────────────────────────────
ASSETS_DIR = Path(__file__).parent / "assets"
if ASSETS_DIR.exists():
    resource_add_path(str(ASSETS_DIR))

ARABIC_FONT = "Roboto"
try:
    LabelBase.register(
        name="Arabic",
        fn_regular=str(ASSETS_DIR / "arabic.ttf"),
    )
    ARABIC_FONT = "Arabic"
except Exception:
    pass


def ar(text):
    """يجهز النص العربي للعرض في Kivy (reshaping + bidi)."""
    if text is None:
        return ""
    text = str(text)
    if not any('\u0600' <= c <= '\u06FF' for c in text):
        return text
    if not ARABIC_OK:
        return text
    try:
        return get_display(arabic_reshaper.reshape(text))
    except Exception:
        return text


# ═══════════════════════════════════════════════════════════════════════════════
#  PATHS & CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
if platform == "android":
    from android.storage import app_storage_path  # type: ignore
    VAULT_DIR = Path(app_storage_path()) / ".nova"
else:
    VAULT_DIR = Path.home() / ".nova_android"

VAULT_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH        = VAULT_DIR / "vault.db"
LOG_PATH       = VAULT_DIR / "audit.log"
LOCK_HASH_PATH = VAULT_DIR / "lock.hash"

T_COST, M_COST, PARALLEL = 3, 64 * 1024, 2
HLEN, SLEN, NLEN = 64, 32, 12

_PEPPER = (b"\x4e\x6f\x76\x61\x5f\x41\x6e\x64\x72\x6f\x69\x64\x5f\x50\x65\x70"
           b"\x5f\x32\x30\x32\x34\x5f\x4d\x6f\x62\x69\x6c\x65\x21\x58\x58\x21")

BG      = (0.027, 0.031, 0.063, 1)
CARD    = (0.075, 0.086, 0.137, 1)
ACCENT  = (0.431, 0.561, 1.0,   1)
SUCCESS = (0.176, 0.855, 0.549, 1)
DANGER  = (1.0,   0.420, 0.420, 1)
WARN    = (1.0,   0.710, 0.278, 1)
TEXT    = (0.941, 0.945, 1.0,   1)
TEXT2   = (0.533, 0.553, 0.690, 1)


# ═══════════════════════════════════════════════════════════════════════════════
#  CRYPTO
# ═══════════════════════════════════════════════════════════════════════════════
def _log(msg):
    try:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception:
        pass


def _kdf(password: str, salt: bytes):
    peppered = hmac.new(_PEPPER, password.encode(), hashlib.sha256).digest()
    raw = hash_secret_raw(peppered, salt,
                          time_cost=T_COST, memory_cost=M_COST,
                          parallelism=PARALLEL, hash_len=HLEN, type=Type.ID)
    return raw[:32], raw[32:]


def _enc(keys, nonce, data, algo="aes"):
    ek, ak = keys
    ct = (AESGCM(ek) if algo == "aes" else ChaCha20Poly1305(ek)).encrypt(nonce, data, ak)
    mac = hmac.new(ak, nonce + ct, hashlib.sha256).digest()
    return mac + ct


def _dec(keys, nonce, blob, algo="aes"):
    ek, ak = keys
    if len(blob) < 32:
        raise ValueError("بيانات ناقصة")
    mac, ct = blob[:32], blob[32:]
    if not hmac.compare_digest(mac, hmac.new(ak, nonce + ct, hashlib.sha256).digest()):
        raise ValueError("كلمة المرور خاطئة أو تم تعديل البيانات")
    return (AESGCM(ek) if algo == "aes" else ChaCha20Poly1305(ek)).decrypt(nonce, ct, ak)


def enc_text(text: str, pw: str, algo="aes") -> str:
    salt  = secrets.token_bytes(SLEN)
    keys  = _kdf(pw, salt)
    nonce = secrets.token_bytes(NLEN)
    ct    = _enc(keys, nonce, text.encode(), algo)
    return base64.b64encode(salt + nonce + ct).decode()


def dec_text(token: str, pw: str, algo="aes") -> str:
    b     = base64.b64decode(token)
    salt  = b[:SLEN]; nonce = b[SLEN:SLEN + NLEN]; ct = b[SLEN + NLEN:]
    keys  = _kdf(pw, salt)
    return _dec(keys, nonce, ct, algo).decode()


def gen_pw(n=20) -> str:
    alpha = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(secrets.choice(alpha) for _ in range(n))


def _db():
    db = sqlite3.connect(str(DB_PATH))
    db.execute("""CREATE TABLE IF NOT EXISTS pw(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, enc TEXT NOT NULL,
        salt TEXT NOT NULL, ts TEXT,
        expires_at TEXT)""")
    db.commit()
    return db


def db_save(name, plain, master):
    db    = _db()
    salt  = secrets.token_bytes(SLEN)
    keys  = _kdf(master, salt)
    nonce = secrets.token_bytes(NLEN)
    ct    = _enc(keys, nonce, plain.encode())
    db.execute("INSERT INTO pw(name,enc,salt,ts) VALUES(?,?,?,?)",
               (name, base64.b64encode(nonce + ct).decode(),
                base64.b64encode(salt).decode(), datetime.now().isoformat()))
    db.commit(); db.close()


def db_load(name, master) -> str:
    db  = _db()
    row = db.execute("SELECT enc,salt FROM pw WHERE name=?", (name,)).fetchone()
    db.close()
    if not row:
        raise ValueError("لا توجد كلمة مرور بهذا الاسم")
    blob  = base64.b64decode(row[0]); salt = base64.b64decode(row[1])
    keys  = _kdf(master, salt)
    return _dec(keys, blob[:NLEN], blob[NLEN:]).decode()


def db_list():
    db = _db()
    rows = db.execute("SELECT name,ts FROM pw ORDER BY ts DESC").fetchall()
    db.close()
    return rows


def db_del(name):
    db = _db()
    db.execute("DELETE FROM pw WHERE name=?", (name,))
    db.commit(); db.close()


def pin_set(pin: str):
    h = hashlib.pbkdf2_hmac("sha256", pin.encode(), _PEPPER, 200_000)
    LOCK_HASH_PATH.write_bytes(h)


def pin_check(pin: str) -> bool:
    if not LOCK_HASH_PATH.exists():
        return False
    h = hashlib.pbkdf2_hmac("sha256", pin.encode(), _PEPPER, 200_000)
    return hmac.compare_digest(h, LOCK_HASH_PATH.read_bytes())


def pin_exists() -> bool:
    return LOCK_HASH_PATH.exists()


# ═══════════════════════════════════════════════════════════════════════════════
#  WIDGETS
# ═══════════════════════════════════════════════════════════════════════════════
def NLabel(text="", size=13, color=TEXT, bold=False, halign="right"):
    lbl = Label(
        text=ar(text),
        font_size=sp(size), color=color, bold=bold, halign=halign,
        size_hint_y=None, font_name=ARABIC_FONT,
    )
    lbl.bind(width=lambda *a: setattr(lbl, "text_size", (lbl.width, None)))
    lbl.bind(texture_size=lambda *a: setattr(lbl, "height", lbl.texture_size[1] + dp(4)))
    return lbl


def NInput(hint="", password=False, multiline=False, height=48):
    return TextInput(
        hint_text=ar(hint), password=password, multiline=multiline,
        background_color=(0.04, 0.05, 0.10, 1),
        foreground_color=(0.941, 0.945, 1.0, 1),
        cursor_color=(0.431, 0.561, 1.0, 1),
        hint_text_color=(0.3, 0.35, 0.5, 1),
        padding=[dp(14), dp(12), dp(14), dp(12)],
        font_size=sp(13), size_hint_y=None, height=dp(height),
        font_name=ARABIC_FONT,
    )


def NBtn(text, color=ACCENT, text_color=(1, 1, 1, 1), on_press=None):
    btn = Button(
        text=ar(text), background_color=color, background_normal="",
        color=text_color, font_size=sp(14), bold=True,
        size_hint_y=None, height=dp(50), font_name=ARABIC_FONT,
    )
    if on_press:
        btn.bind(on_press=on_press)
    return btn


def space(h=12):
    return Widget(size_hint_y=None, height=dp(h))


def show_toast(msg, color=SUCCESS):
    popup = Popup(
        title="", size_hint=(None, None), size=(dp(300), dp(80)),
        background_color=(0.075, 0.086, 0.137, 1),
        border=(0, 0, 0, 0), separator_height=0,
    )
    lbl = Label(text=ar(msg), color=color, font_size=sp(13),
                halign="center", font_name=ARABIC_FONT)
    popup.add_widget(lbl)
    popup.open()
    Clock.schedule_once(lambda dt: popup.dismiss(), 2.5)


def confirm_dialog(title, msg, on_yes):
    content = BoxLayout(orientation="vertical", spacing=dp(12), padding=dp(16))
    content.add_widget(Label(
        text=ar(msg), color=TEXT, font_size=sp(13),
        halign="center", size_hint_y=None, height=dp(50),
        font_name=ARABIC_FONT,
    ))
    btns = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
    popup = Popup(
        title=ar(title), content=content,
        size_hint=(None, None), size=(dp(300), dp(180)),
        background_color=(0.075, 0.086, 0.137, 1),
    )
    yes_btn = NBtn("تأكيد", color=DANGER)
    no_btn  = NBtn("إلغاء", color=(0.2, 0.2, 0.3, 1))

    def do_yes(i):
        popup.dismiss(); on_yes()

    yes_btn.bind(on_press=do_yes)
    no_btn.bind(on_press=lambda i: popup.dismiss())
    btns.add_widget(yes_btn); btns.add_widget(no_btn)
    content.add_widget(btns)
    popup.open()


def _page_wrap(title, icon="🔒"):
    root = BoxLayout(orientation="vertical", size_hint=(1, 1))
    with root.canvas.before:
        Color(*BG)
        rect = Rectangle(size=root.size, pos=root.pos)
    root.bind(size=lambda *a: setattr(rect, "size", root.size))
    root.bind(pos=lambda *a: setattr(rect, "pos", root.pos))

    tb = BoxLayout(size_hint_y=None, height=dp(58),
                   padding=[dp(16), 0, dp(16), 0])
    with tb.canvas.before:
        Color(0.055, 0.063, 0.106, 1)
        tb_rect = Rectangle(size=tb.size, pos=tb.pos)
    tb.bind(size=lambda *a: setattr(tb_rect, "size", tb.size))
    tb.bind(pos=lambda *a: setattr(tb_rect, "pos", tb.pos))

    tb.add_widget(Label(
        text=ar(f"{icon}  {title}"), font_size=sp(17), bold=True,
        color=TEXT, halign="right", size_hint_x=1,
        font_name=ARABIC_FONT,
    ))
    root.add_widget(tb)

    content = BoxLayout(orientation="vertical", spacing=dp(14), padding=dp(16),
                        size_hint_y=None)
    content.bind(minimum_height=content.setter("height"))
    sv = ScrollView(do_scroll_x=False)
    sv.add_widget(content)
    root.add_widget(sv)
    return root, content


def _card(content):
    box = BoxLayout(orientation="vertical", spacing=dp(10),
                    padding=dp(16), size_hint_y=None)
    box.bind(minimum_height=box.setter("height"))
    with box.canvas.before:
        Color(*CARD)
        rrect = RoundedRectangle(radius=[dp(16)], size=box.size, pos=box.pos)
    box.bind(size=lambda *a: setattr(rrect, "size", box.size))
    box.bind(pos=lambda *a: setattr(rrect, "pos", box.pos))
    content.add_widget(box)
    return box


# ═══════════════════════════════════════════════════════════════════════════════
#  SCREENS
# ═══════════════════════════════════════════════════════════════════════════════
class HomeScreen(Screen):
    def __init__(self, app_ref, **kw):
        super().__init__(name="home", **kw)
        self.app_ref = app_ref
        self.build_ui()

    def build_ui(self):
        root, content = _page_wrap("Nova Vault", "🔐")
        hero = _card(content)
        hero.add_widget(Label(text="🔐", font_size=sp(48),
                              size_hint_y=None, height=dp(70),
                              halign="center", font_name=ARABIC_FONT))
        hero.add_widget(NLabel("Nova Vault", size=22, bold=True, halign="center"))
        hero.add_widget(NLabel("خزنة التشفير الشخصية", size=13,
                               color=TEXT2, halign="center"))
        hero.add_widget(space(8))
        if not CRYPTO_OK:
            hero.add_widget(NLabel("⚠ مكتبات التشفير غير مثبتة",
                                   color=WARN, halign="center"))

        stats = GridLayout(cols=2, spacing=dp(8), size_hint_y=None, height=dp(120))
        for val, lbl, col in [
            ("AES-256", "خوارزمية التشفير", ACCENT),
            ("Argon2id", "اشتقاق المفتاح", SUCCESS),
            (str(len(db_list())), "كلمات مرور محفوظة", WARN),
            ("0", "بيانات على الإنترنت", (0.7, 0.7, 0.8, 1)),
        ]:
            box = BoxLayout(orientation="vertical", padding=dp(12))
            with box.canvas.before:
                Color(0.1, 0.12, 0.18, 1)
                rr = RoundedRectangle(radius=[dp(12)], size=box.size, pos=box.pos)
            box.bind(size=lambda a, b, r=rr: setattr(r, "size", a.size))
            box.bind(pos=lambda a, b, r=rr: setattr(r, "pos", a.pos))
            box.add_widget(Label(text=ar(val), font_size=sp(20), bold=True,
                                 color=col, size_hint_y=None, height=dp(32),
                                 halign="center", font_name=ARABIC_FONT))
            box.add_widget(Label(text=ar(lbl), font_size=sp(10), color=TEXT2,
                                 halign="center", font_name=ARABIC_FONT))
            stats.add_widget(box)
        content.add_widget(stats)

        content.add_widget(NLabel("إجراءات سريعة", size=14, bold=True))

        actions = [
            ("🔒  تشفير نص",         "enc",  ACCENT),
            ("🔓  فك التشفير",       "dec",  (0.4, 0.4, 0.9, 1)),
            ("💾  حفظ كلمة مرور",    "save", SUCCESS),
            ("🎲  توليد كلمة مرور",  "gen",  WARN),
            ("📋  قائمة كلمات المرور", "list", (0.5, 0.5, 0.8, 1)),
            ("🔐  إعداد رمز PIN",     "pin",  DANGER),
        ]
        grid = GridLayout(cols=2, spacing=dp(8), size_hint_y=None)
        grid.bind(minimum_height=grid.setter("height"))
        for label, key, col in actions:
            btn = Button(
                text=ar(label),
                background_color=col[:3] + (0.15,),
                background_normal="", color=col,
                font_size=sp(13), bold=True,
                size_hint_y=None, height=dp(56),
                font_name=ARABIC_FONT,
            )
            with btn.canvas.before:
                Color(*col[:3], 0.2)
                rr = RoundedRectangle(radius=[dp(12)], size=btn.size, pos=btn.pos)
            btn.bind(size=lambda a, b, r=rr: setattr(r, "size", a.size))
            btn.bind(pos=lambda a, b, r=rr: setattr(r, "pos", a.pos))
            btn.bind(on_press=lambda _, k=key: self.app_ref.go(k))
            grid.add_widget(btn)
        content.add_widget(grid)
        content.add_widget(space(20))
        self.add_widget(root)


class EncScreen(Screen):
    def __init__(self, app_ref, **kw):
        super().__init__(name="enc", **kw)
        self.app_ref = app_ref
        self.build_ui()

    def build_ui(self):
        root, content = _page_wrap("تشفير نص", "🔒")
        card = _card(content)

        card.add_widget(NLabel("النص", size=13, bold=True))
        self.txt_in = NInput("اكتب النص المراد تشفيره...",
                             multiline=True, height=120)
        card.add_widget(self.txt_in)

        card.add_widget(NLabel("كلمة المرور", size=13, bold=True))
        pw_row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8))
        self.pw_in = NInput("كلمة المرور", password=True)
        self.pw_in.size_hint_x = 0.75
        gen_btn = Button(text="🎲", background_color=WARN,
                         background_normal="", color=(0.1, 0.1, 0.1, 1),
                         bold=True, size_hint_x=0.25,
                         size_hint_y=None, height=dp(48),
                         font_name=ARABIC_FONT)
        gen_btn.bind(on_press=lambda _: setattr(self.pw_in, "text", gen_pw(16)))
        pw_row.add_widget(self.pw_in); pw_row.add_widget(gen_btn)
        card.add_widget(pw_row)

        algo_row = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(8))
        algo_row.add_widget(NLabel("الخوارزمية:", size=12, color=TEXT2))
        self.algo_var = "aes"
        self.btn_aes = Button(text="AES-256", background_color=ACCENT,
                              background_normal="", color=(1, 1, 1, 1),
                              bold=True, size_hint_y=None, height=dp(36),
                              font_name=ARABIC_FONT)
        self.btn_ch = Button(text="ChaCha20",
                             background_color=(0.15, 0.15, 0.25, 1),
                             background_normal="", color=TEXT2,
                             size_hint_y=None, height=dp(36),
                             font_name=ARABIC_FONT)
        self.btn_aes.bind(on_press=lambda _: self.set_algo("aes"))
        self.btn_ch.bind(on_press=lambda _: self.set_algo("chacha"))
        algo_row.add_widget(self.btn_aes); algo_row.add_widget(self.btn_ch)
        card.add_widget(algo_row)

        card.add_widget(NLabel("الناتج المشفّر", size=13, bold=True))
        self.out = NInput("سيظهر هنا النص المشفّر...",
                          multiline=True, height=120)
        self.out.readonly = True
        self.out.foreground_color = (*SUCCESS[:3], 1)
        card.add_widget(self.out)

        self.status_lbl = NLabel("", size=11, color=TEXT2)
        card.add_widget(self.status_lbl)

        btns = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(8))
        enc_btn  = NBtn("🔒  تشفير", color=SUCCESS, text_color=(0.02, 0.1, 0.04, 1))
        copy_btn = NBtn("📋  نسخ", color=(0.2, 0.2, 0.35, 1))
        enc_btn.bind(on_press=lambda _: self.do_enc())
        copy_btn.bind(on_press=lambda _: self.do_copy())
        btns.add_widget(enc_btn); btns.add_widget(copy_btn)
        card.add_widget(btns)

        back_btn = NBtn("→  رجوع", color=(0.1, 0.12, 0.20, 1))
        back_btn.bind(on_press=lambda _: self.app_ref.go("home"))
        content.add_widget(back_btn)
        content.add_widget(space(20))
        self.add_widget(root)

    def set_algo(self, v):
        self.algo_var = v
        self.btn_aes.background_color = ACCENT if v == "aes" else (0.15, 0.15, 0.25, 1)
        self.btn_ch.background_color  = ACCENT if v == "chacha" else (0.15, 0.15, 0.25, 1)
        self.btn_aes.color = (1, 1, 1, 1) if v == "aes" else TEXT2
        self.btn_ch.color  = (1, 1, 1, 1) if v == "chacha" else TEXT2

    def do_enc(self):
        if not CRYPTO_OK:
            show_toast("مكتبات التشفير غير مثبتة", DANGER); return
        txt = self.txt_in.text.strip(); pw = self.pw_in.text
        if not txt or not pw:
            show_toast("النص وكلمة المرور مطلوبان", WARN); return
        self.out.text = "⏳ جارٍ التشفير..."
        self.status_lbl.text = ""

        def task(dt):
            try:
                r = enc_text(txt, pw, self.algo_var)
                self.out.text = r
                self.status_lbl.text = ar("✓ تم التشفير")
                self.status_lbl.color = SUCCESS
            except Exception as e:
                self.out.text = ar(f"خطأ: {e}")
                self.status_lbl.color = DANGER

        Clock.schedule_once(task, 0.05)

    def do_copy(self):
        if self.out.text:
            Clipboard.copy(self.out.text)
            show_toast("✓ تم النسخ إلى الحافظة", SUCCESS)


class DecScreen(Screen):
    def __init__(self, app_ref, **kw):
        super().__init__(name="dec", **kw)
        self.app_ref = app_ref
        self.build_ui()

    def build_ui(self):
        root, content = _page_wrap("فك التشفير", "🔓")
        card = _card(content)

        card.add_widget(NLabel("النص المشفّر", size=13, bold=True))
        paste_row = BoxLayout(size_hint_y=None, height=dp(36))
        paste_row.add_widget(Widget())
        paste_btn = Button(text=ar("📋 لصق"), size_hint_x=None, width=dp(90),
                           background_color=ACCENT, background_normal="",
                           color=(1, 1, 1, 1), bold=True,
                           size_hint_y=None, height=dp(34),
                           font_name=ARABIC_FONT)
        paste_row.add_widget(paste_btn)
        card.add_widget(paste_row)

        self.txt_in = NInput("الصق النص المشفّر هنا...",
                             multiline=True, height=130)
        paste_btn.bind(on_press=lambda _: setattr(
            self.txt_in, "text", Clipboard.paste() or ""))
        card.add_widget(self.txt_in)

        card.add_widget(NLabel("كلمة المرور", size=13, bold=True))
        self.pw_in = NInput("كلمة المرور", password=True)
        card.add_widget(self.pw_in)

        algo_row = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(8))
        algo_row.add_widget(NLabel("الخوارزمية:", size=12, color=TEXT2))
        self.algo_var = "aes"
        self.btn_aes = Button(text="AES-256", background_color=ACCENT,
                              background_normal="", color=(1, 1, 1, 1),
                              bold=True, size_hint_y=None, height=dp(36),
                              font_name=ARABIC_FONT)
        self.btn_ch = Button(text="ChaCha20",
                             background_color=(0.15, 0.15, 0.25, 1),
                             background_normal="", color=TEXT2,
                             size_hint_y=None, height=dp(36),
                             font_name=ARABIC_FONT)
        self.btn_aes.bind(on_press=lambda _: self._set_algo("aes"))
        self.btn_ch.bind(on_press=lambda _: self._set_algo("chacha"))
        algo_row.add_widget(self.btn_aes); algo_row.add_widget(self.btn_ch)
        card.add_widget(algo_row)

        card.add_widget(NLabel("النص الأصلي", size=13, bold=True))
        self.out = NInput("", multiline=True, height=120)
        self.out.readonly = True
        self.out.foreground_color = (*SUCCESS[:3], 1)
        card.add_widget(self.out)

        self.status_lbl = NLabel("", size=11, color=TEXT2)
        card.add_widget(self.status_lbl)

        btns = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(8))
        dec_btn  = NBtn("🔓  فك التشفير", color=ACCENT)
        copy_btn = NBtn("📋  نسخ", color=(0.2, 0.2, 0.35, 1))
        dec_btn.bind(on_press=lambda _: self.do_dec())
        copy_btn.bind(on_press=lambda _: (Clipboard.copy(self.out.text),
                                          show_toast("✓ تم النسخ", SUCCESS)))
        btns.add_widget(dec_btn); btns.add_widget(copy_btn)
        card.add_widget(btns)

        back_btn = NBtn("→  رجوع", color=(0.1, 0.12, 0.20, 1))
        back_btn.bind(on_press=lambda _: self.app_ref.go("home"))
        content.add_widget(back_btn)
        content.add_widget(space(20))
        self.add_widget(root)

    def _set_algo(self, v):
        self.algo_var = v
        self.btn_aes.background_color = ACCENT if v == "aes" else (0.15, 0.15, 0.25, 1)
        self.btn_ch.background_color  = ACCENT if v == "chacha" else (0.15, 0.15, 0.25, 1)

    def do_dec(self):
        if not CRYPTO_OK:
            show_toast("مكتبات التشفير غير مثبتة", DANGER); return
        token = self.txt_in.text.strip(); pw = self.pw_in.text
        if not token or not pw:
            show_toast("النص وكلمة المرور مطلوبان", WARN); return
        self.out.text = "⏳ جارٍ فك التشفير..."

        def task(dt):
            try:
                r = dec_text(token, pw, self.algo_var)
                self.out.text = r
                self.status_lbl.text = ar("✓ تم فك التشفير")
                self.status_lbl.color = SUCCESS
            except Exception as e:
                self.out.text = ar(f"فشل: {e}")
                self.status_lbl.color = DANGER

        Clock.schedule_once(task, 0.05)


class SavePwScreen(Screen):
    def __init__(self, app_ref, **kw):
        super().__init__(name="save", **kw)
        self.app_ref = app_ref
        self.build_ui()

    def build_ui(self):
        root, content = _page_wrap("حفظ كلمة مرور", "💾")
        card = _card(content)

        card.add_widget(NLabel("اسم الخدمة", size=13, bold=True))
        self.nm = NInput("مثال: gmail أو facebook")
        card.add_widget(self.nm)

        card.add_widget(NLabel("كلمة المرور", size=13, bold=True))
        pw_row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8))
        self.pw = NInput("كلمة المرور")
        self.pw.size_hint_x = 0.75
        gen_btn = Button(text="🎲", background_color=WARN, background_normal="",
                         color=(0.1, 0.1, 0.1, 1), bold=True,
                         size_hint_x=0.25, size_hint_y=None, height=dp(48),
                         font_name=ARABIC_FONT)
        gen_btn.bind(on_press=lambda _: (
            setattr(self.pw, "text", gen_pw(20)),
            show_toast("✓ تم توليد كلمة مرور قوية", SUCCESS)))
        pw_row.add_widget(self.pw); pw_row.add_widget(gen_btn)
        card.add_widget(pw_row)

        card.add_widget(NLabel("كلمة المرور الرئيسية", size=13,
                               bold=True, color=WARN))
        self.m1 = NInput("كلمة المرور الرئيسية", password=True)
        card.add_widget(self.m1)

        card.add_widget(NLabel("تأكيد كلمة المرور الرئيسية", size=13, bold=True))
        self.m2 = NInput("أعد إدخال كلمة المرور", password=True)
        card.add_widget(self.m2)

        self.status = NLabel("", size=11, color=TEXT2)
        card.add_widget(self.status)

        save_btn = NBtn("💾  حفظ", color=SUCCESS, text_color=(0.02, 0.1, 0.04, 1))
        save_btn.bind(on_press=lambda _: self.do_save())
        card.add_widget(save_btn)

        back_btn = NBtn("→  رجوع", color=(0.1, 0.12, 0.20, 1))
        back_btn.bind(on_press=lambda _: self.app_ref.go("home"))
        content.add_widget(back_btn)
        content.add_widget(space(20))
        self.add_widget(root)

    def do_save(self):
        if not CRYPTO_OK:
            show_toast("مكتبات التشفير غير مثبتة", DANGER); return
        n, p, a, b = (self.nm.text.strip(), self.pw.text,
                      self.m1.text, self.m2.text)
        if not all([n, p, a, b]):
            self.status.text = ar("جميع الحقول مطلوبة")
            self.status.color = DANGER; return
        if a != b:
            self.status.text = ar("كلمة المرور الرئيسية غير متطابقة")
            self.status.color = DANGER; return
        self.status.text = ar("⏳ جارٍ الحفظ...")
        self.status.color = TEXT2

        def task(dt):
            try:
                db_save(n, p, a)
                self.status.text = ar(f"✓ تم حفظ '{n}'")
                self.status.color = SUCCESS
                for e in (self.nm, self.pw, self.m1, self.m2):
                    e.text = ""
            except Exception as e:
                self.status.text = ar(f"خطأ: {e}")
                self.status.color = DANGER

        Clock.schedule_once(task, 0.05)


class LoadPwScreen(Screen):
    def __init__(self, app_ref, **kw):
        super().__init__(name="load", **kw)
        self.app_ref = app_ref
        self.build_ui()

    def build_ui(self):
        root, content = _page_wrap("عرض كلمة مرور", "🔑")
        card = _card(content)

        card.add_widget(NLabel("اسم الخدمة", size=13, bold=True))
        self.nm = NInput("اسم الخدمة")
        card.add_widget(self.nm)

        card.add_widget(NLabel("كلمة المرور الرئيسية", size=13,
                               bold=True, color=WARN))
        self.m1 = NInput("كلمة المرور الرئيسية", password=True)
        card.add_widget(self.m1)

        self.result_lbl = Label(text="—", font_size=sp(20), bold=True,
                                color=SUCCESS, size_hint_y=None, height=dp(50),
                                halign="center", font_name=ARABIC_FONT)
        card.add_widget(self.result_lbl)

        self.status = NLabel("", size=11, color=TEXT2)
        card.add_widget(self.status)

        btns = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(8))
        load_btn = NBtn("🔑  عرض", color=ACCENT)
        copy_btn = NBtn("📋  نسخ", color=(0.2, 0.2, 0.35, 1))
        load_btn.bind(on_press=lambda _: self.do_load())
        copy_btn.bind(on_press=lambda _: self.do_copy())
        btns.add_widget(load_btn); btns.add_widget(copy_btn)
        card.add_widget(btns)

        back_btn = NBtn("→  رجوع", color=(0.1, 0.12, 0.20, 1))
        back_btn.bind(on_press=lambda _: self.app_ref.go("home"))
        content.add_widget(back_btn)
        content.add_widget(space(20))
        self.add_widget(root)

    def do_load(self):
        if not CRYPTO_OK:
            show_toast("مكتبات التشفير غير مثبتة", DANGER); return
        n, m = self.nm.text.strip(), self.m1.text
        if not n or not m:
            show_toast("الاسم وكلمة المرور الرئيسية مطلوبان", WARN); return
        self.result_lbl.text = "⏳..."
        self.status.text = ""

        def task(dt):
            try:
                pw = db_load(n, m)
                self.result_lbl.text = pw
                self.result_lbl.color = SUCCESS
                self.status.text = ar("✓ تم")
                self.status.color = SUCCESS
            except Exception as e:
                self.result_lbl.text = "—"
                self.status.text = ar(f"خطأ: {e}")
                self.status.color = DANGER

        Clock.schedule_once(task, 0.05)

    def do_copy(self):
        txt = self.result_lbl.text
        if txt and txt != "—":
            Clipboard.copy(txt)
            show_toast("✓ تم النسخ", SUCCESS)


class GenPwScreen(Screen):
    def __init__(self, app_ref, **kw):
        super().__init__(name="gen", **kw)
        self.app_ref = app_ref
        self.build_ui()

    def build_ui(self):
        from kivy.uix.slider import Slider
        root, content = _page_wrap("توليد كلمة مرور", "🎲")
        card = _card(content)

        len_row = BoxLayout(size_hint_y=None, height=dp(36))
        len_row.add_widget(NLabel("الطول:", size=13, bold=True))
        self.len_lbl = Label(text="20", font_size=sp(20), bold=True,
                             color=ACCENT, size_hint_y=None, height=dp(36),
                             font_name=ARABIC_FONT)
        len_row.add_widget(self.len_lbl)
        card.add_widget(len_row)

        self.slider = Slider(min=8, max=64, value=20, step=1,
                             size_hint_y=None, height=dp(44),
                             cursor_size=(dp(22), dp(22)))
        self.slider.bind(value=lambda _, v: setattr(
            self.len_lbl, "text", str(int(v))))
        card.add_widget(self.slider)

        self.pw_display = Label(
            text=ar("اضغط توليد"), font_size=sp(16), bold=True,
            color=SUCCESS, size_hint_y=None, height=dp(70),
            halign="center", font_name=ARABIC_FONT,
        )
        with self.pw_display.canvas.before:
            Color(0.04, 0.06, 0.12, 1)
            rr = RoundedRectangle(radius=[dp(12)],
                                  size=self.pw_display.size,
                                  pos=self.pw_display.pos)
        self.pw_display.bind(size=lambda *a: setattr(rr, "size", self.pw_display.size))
        self.pw_display.bind(pos=lambda *a: setattr(rr, "pos", self.pw_display.pos))
        card.add_widget(self.pw_display)

        btns = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(8))
        gen_btn  = NBtn("🎲  توليد", color=SUCCESS, text_color=(0.02, 0.1, 0.04, 1))
        copy_btn = NBtn("📋  نسخ", color=ACCENT)
        gen_btn.bind(on_press=lambda _: self.do_gen())
        copy_btn.bind(on_press=lambda _: self.do_copy())
        btns.add_widget(gen_btn); btns.add_widget(copy_btn)
        card.add_widget(btns)

        back_btn = NBtn("→  رجوع", color=(0.1, 0.12, 0.20, 1))
        back_btn.bind(on_press=lambda _: self.app_ref.go("home"))
        content.add_widget(back_btn)
        content.add_widget(space(20))
        self.add_widget(root)
        self.do_gen()

    def do_gen(self):
        self.pw_display.text = gen_pw(int(self.slider.value))

    def do_copy(self):
        t = self.pw_display.text
        if t and t != ar("اضغط توليد"):
            Clipboard.copy(t)
            show_toast("✓ تم النسخ", SUCCESS)


class ListPwScreen(Screen):
    def __init__(self, app_ref, **kw):
        super().__init__(name="list", **kw)
        self.app_ref = app_ref
        self.build_ui()

    def on_pre_enter(self):
        self.refresh()

    def build_ui(self):
        root, content = _page_wrap("كلمات المرور", "📋")
        self.content = content

        ref_btn = NBtn("🔄  تحديث", color=(0.15, 0.18, 0.28, 1))
        ref_btn.bind(on_press=lambda _: self.refresh())
        content.add_widget(ref_btn)

        self.list_box = BoxLayout(orientation="vertical", spacing=dp(6),
                                  size_hint_y=None)
        self.list_box.bind(minimum_height=self.list_box.setter("height"))
        content.add_widget(self.list_box)

        back_btn = NBtn("→  رجوع", color=(0.1, 0.12, 0.20, 1))
        back_btn.bind(on_press=lambda _: self.app_ref.go("home"))
        content.add_widget(back_btn)
        content.add_widget(space(20))
        self.add_widget(root)

    def refresh(self):
        self.list_box.clear_widgets()
        rows = db_list()
        if not rows:
            self.list_box.add_widget(NLabel("الخزنة فارغة", size=13,
                                            color=TEXT2, halign="center"))
            return
        for name, ts in rows:
            row = BoxLayout(size_hint_y=None, height=dp(56),
                            padding=[dp(14), 0, dp(8), 0], spacing=dp(8))
            with row.canvas.before:
                Color(0.1, 0.12, 0.18, 1)
                rr = RoundedRectangle(radius=[dp(12)], size=row.size, pos=row.pos)
            row.bind(size=lambda a, b, r=rr: setattr(r, "size", a.size))
            row.bind(pos=lambda a, b, r=rr: setattr(r, "pos", a.pos))
            row.add_widget(Label(text=ar(f"🔑  {name}"), font_size=sp(13),
                                 color=TEXT, halign="right", bold=True,
                                 size_hint_x=0.65, font_name=ARABIC_FONT))
            del_btn = Button(text="🗑", background_color=(*DANGER[:3], 0.2),
                             background_normal="", color=DANGER,
                             bold=True, size_hint_x=0.15,
                             size_hint_y=None, height=dp(36),
                             font_name=ARABIC_FONT)
            del_btn.bind(on_press=lambda _, n=name: confirm_dialog(
                "حذف", f"حذف '{n}'؟",
                lambda nm=n: (db_del(nm), self.refresh(),
                              show_toast(f"✓ تم حذف '{nm}'", SUCCESS))))
            row.add_widget(del_btn)
            self.list_box.add_widget(row)


class PinScreen(Screen):
    def __init__(self, app_ref, **kw):
        super().__init__(name="pin", **kw)
        self.app_ref = app_ref
        self.build_ui()

    def build_ui(self):
        root, content = _page_wrap("إعداد رمز PIN", "🔐")
        card = _card(content)

        status_text = ("✓ رمز PIN مفعّل — التطبيق يُقفل تلقائياً"
                       if pin_exists() else
                       "⚠ لا يوجد رمز PIN — التطبيق مفتوح")
        status_col = SUCCESS if pin_exists() else WARN
        card.add_widget(NLabel(status_text, size=12, color=status_col))
        card.add_widget(space(4))

        card.add_widget(NLabel("رمز PIN الجديد", size=13, bold=True))
        self.p1 = NInput("رمز PIN (4 أحرف على الأقل)", password=True)
        card.add_widget(self.p1)

        card.add_widget(NLabel("تأكيد رمز PIN", size=13, bold=True))
        self.p2 = NInput("أعد إدخال رمز PIN", password=True)
        card.add_widget(self.p2)

        self.status = NLabel("", size=11, color=TEXT2)
        card.add_widget(self.status)

        btns = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(8))
        save_btn = NBtn("💾  حفظ رمز PIN", color=SUCCESS,
                        text_color=(0.02, 0.1, 0.04, 1))
        del_btn  = NBtn("🗑  حذف", color=(*DANGER[:3], 0.3))
        del_btn.color = DANGER
        save_btn.bind(on_press=lambda _: self.save_pin())
        del_btn.bind(on_press=lambda _: self.remove_pin())
        btns.add_widget(save_btn); btns.add_widget(del_btn)
        card.add_widget(btns)

        back_btn = NBtn("→  رجوع", color=(0.1, 0.12, 0.20, 1))
        back_btn.bind(on_press=lambda _: self.app_ref.go("home"))
        content.add_widget(back_btn)
        content.add_widget(space(20))
        self.add_widget(root)

    def save_pin(self):
        a, b = self.p1.text, self.p2.text
        if len(a) < 4:
            self.status.text = ar("رمز PIN يجب ألا يقل عن 4 أحرف")
            self.status.color = DANGER; return
        if a != b:
            self.status.text = ar("رمز PIN غير متطابق")
            self.status.color = DANGER; return
        pin_set(a)
        self.status.text = ar("✓ تم حفظ رمز PIN")
        self.status.color = SUCCESS
        self.p1.text = ""; self.p2.text = ""

    def remove_pin(self):
        if LOCK_HASH_PATH.exists():
            LOCK_HASH_PATH.unlink()
            self.status.text = ar("✓ تم حذف رمز PIN")
            self.status.color = WARN


class LockScreen(Screen):
    def __init__(self, app_ref, **kw):
        super().__init__(name="lock", **kw)
        self.app_ref = app_ref
        self.build_ui()

    def build_ui(self):
        root = BoxLayout(orientation="vertical")
        with root.canvas.before:
            Color(*BG)
            rect = Rectangle(size=root.size, pos=root.pos)
        root.bind(size=lambda *a: setattr(rect, "size", root.size))
        root.bind(pos=lambda *a: setattr(rect, "pos", root.pos))

        root.add_widget(Widget())
        center = BoxLayout(orientation="vertical", spacing=dp(16),
                           padding=[dp(40), 0, dp(40), 0],
                           size_hint_y=None, height=dp(340))
        center.add_widget(Label(text="🔐", font_size=sp(60),
                                size_hint_y=None, height=dp(80),
                                halign="center", font_name=ARABIC_FONT))
        center.add_widget(Label(text=ar("Nova Vault مقفل"),
                                font_size=sp(22), bold=True, color=TEXT,
                                size_hint_y=None, height=dp(40),
                                halign="center", font_name=ARABIC_FONT))
        center.add_widget(Label(text=ar("أدخل رمز PIN للمتابعة"),
                                font_size=sp(13), color=TEXT2,
                                size_hint_y=None, height=dp(30),
                                halign="center", font_name=ARABIC_FONT))
        self.pin_in = NInput("● ● ● ●", password=True)
        center.add_widget(self.pin_in)
        self.err_lbl = Label(text="", font_size=sp(12), color=DANGER,
                             size_hint_y=None, height=dp(28),
                             halign="center", font_name=ARABIC_FONT)
        center.add_widget(self.err_lbl)
        unlock_btn = NBtn("🔓  فتح", color=ACCENT)
        unlock_btn.bind(on_press=lambda _: self.try_unlock())
        center.add_widget(unlock_btn)
        root.add_widget(center)
        root.add_widget(Widget())
        self.add_widget(root)

    def try_unlock(self):
        if pin_check(self.pin_in.text):
            self.pin_in.text = ""; self.err_lbl.text = ""
            self.app_ref.go("home")
        else:
            self.err_lbl.text = ar("رمز PIN خاطئ — حاول مجدداً")
            self.pin_in.text = ""


# ═══════════════════════════════════════════════════════════════════════════════
#  APP
# ═══════════════════════════════════════════════════════════════════════════════
class NovaAndroidApp(MDApp if USE_MD else App):
    def build(self):
        Window.clearcolor = BG
        if USE_MD:
            self.theme_cls.theme_style = "Dark"
            self.theme_cls.primary_palette = "Blue"
        self.sm = ScreenManager(transition=SlideTransition())
        for S in (HomeScreen, EncScreen, DecScreen, SavePwScreen,
                  LoadPwScreen, GenPwScreen, ListPwScreen,
                  PinScreen, LockScreen):
            self.sm.add_widget(S(self))
        if pin_exists():
            self.sm.current = "lock"
        return self.sm

    def go(self, name):
        if name in [s.name for s in self.sm.screens]:
            self.sm.current = name

    def get_application_name(self):
        return "Nova Vault"


if __name__ == "__main__":
    NovaAndroidApp().run()