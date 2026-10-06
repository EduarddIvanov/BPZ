import sys

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QPlainTextEdit, QComboBox, QSpinBox,
    QLabel, QLineEdit, QWidget, QVBoxLayout, QHBoxLayout,
    QMessageBox, QFileDialog, QDialog, QDialogButtonBox,
)
from PySide6.QtGui import QAction, QTextDocument
from PySide6.QtPrintSupport import QPrintPreviewDialog, QPrinter

from trithemius import (
    TrithemiusCipher, LinearKey, NonlinearKey, KeywordKey, CipherError,
)
from trithemius_attack import KnownPlaintextAttack

DEVELOPER = "Іванов Едуард Костянтинович"
GROUP = "ТВ-33"


class AttackDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Атака за відомим відкритим текстом")
        self.resize(560, 240)

        self.plain = QPlainTextEdit()
        self.cipher = QPlainTextEdit()

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Відкритий текст:"))
        layout.addWidget(self.plain)
        layout.addWidget(QLabel("Відповідний шифртекст:"))
        layout.addWidget(self.cipher)
        layout.addWidget(buttons)

    def texts(self):
        return self.plain.toPlainText(), self.cipher.toPlainText()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Шифр Тритеміуса — криптосистема")
        self.resize(780, 580)
        self.current_path = None

        self._build_ui()
        self._build_actions()
        self._build_menu()
        self._build_toolbar()

    def _build_ui(self):
        self.editor = QPlainTextEdit()

        self.lang_box = QComboBox()
        self.lang_box.addItem("Українська", "uk")
        self.lang_box.addItem("English", "en")

        self.key_type_box = QComboBox()
        self.key_type_box.addItem("Лінійний (A, B)", "linear")
        self.key_type_box.addItem("Нелінійний (A, B, C)", "nonlinear")
        self.key_type_box.addItem("Гасло", "keyword")
        self.key_type_box.currentIndexChanged.connect(self._on_key_type_changed)

        # поля ключа перемикаються залежно від обраного типу
        self.a_spin = self._make_spin(1)
        self.b_spin = self._make_spin(1)
        self.c_spin = self._make_spin(0)
        self.keyword_edit = QLineEdit("ключ")

        top = QHBoxLayout()
        top.addWidget(QLabel("Мова:"))
        top.addWidget(self.lang_box)
        top.addSpacing(15)
        top.addWidget(QLabel("Тип ключа:"))
        top.addWidget(self.key_type_box)
        top.addStretch()

        self.key_row = QHBoxLayout()
        self.key_row.addWidget(QLabel("Ключ:"))
        self.key_row.addWidget(QLabel("A:"))
        self.key_row.addWidget(self.a_spin)
        self.key_row.addWidget(QLabel("B:"))
        self.key_row.addWidget(self.b_spin)
        self._c_label = QLabel("C:")
        self.key_row.addWidget(self._c_label)
        self.key_row.addWidget(self.c_spin)
        self._kw_label = QLabel("Гасло:")
        self.key_row.addWidget(self._kw_label)
        self.key_row.addWidget(self.keyword_edit)
        self.key_row.addStretch()

        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addLayout(self.key_row)
        layout.addWidget(self.editor)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        self.statusBar().showMessage("Готово")
        self._on_key_type_changed()

    def _make_spin(self, value):
        spin = QSpinBox()
        spin.setRange(-99, 99)
        spin.setValue(value)
        return spin

    def _on_key_type_changed(self):
        kind = self.key_type_box.currentData()
        show_c = kind == "nonlinear"
        show_coeffs = kind in ("linear", "nonlinear")
        self.a_spin.setVisible(show_coeffs)
        self.b_spin.setVisible(show_coeffs)
        self.c_spin.setVisible(show_c)
        self._c_label.setVisible(show_c)
        self.keyword_edit.setVisible(kind == "keyword")
        self._kw_label.setVisible(kind == "keyword")

    def _build_actions(self):
        self.act_new = QAction("Створити", self, triggered=self.new_file)
        self.act_open = QAction("Відкрити", self, triggered=self.open_file)
        self.act_save = QAction("Зберегти", self, triggered=self.save_file)
        self.act_print = QAction("Друк (перегляд)", self, triggered=self.print_preview)
        self.act_exit = QAction("Вихід", self, triggered=self.close)

        self.act_encrypt = QAction("Зашифрувати", self, triggered=self.encrypt)
        self.act_decrypt = QAction("Розшифрувати", self, triggered=self.decrypt)
        self.act_attack = QAction("Атака (відомий текст)", self, triggered=self.attack)

        self.act_about = QAction("Про розробника", self, triggered=self.about)

    def _build_menu(self):
        menubar = self.menuBar()

        m_file = menubar.addMenu("Файл")
        m_file.addActions([self.act_new, self.act_open, self.act_save])
        m_file.addSeparator()
        m_file.addAction(self.act_print)
        m_file.addSeparator()
        m_file.addAction(self.act_exit)

        m_crypto = menubar.addMenu("Шифрування")
        m_crypto.addActions([self.act_encrypt, self.act_decrypt])
        m_crypto.addSeparator()
        m_crypto.addAction(self.act_attack)

        m_help = menubar.addMenu("Довідка")
        m_help.addAction(self.act_about)

    def _build_toolbar(self):
        tb = self.addToolBar("Основне")
        tb.addActions([self.act_new, self.act_open, self.act_save, self.act_print])
        tb.addSeparator()
        tb.addActions([self.act_encrypt, self.act_decrypt, self.act_attack])

    def _lang(self):
        return self.lang_box.currentData()

    def _build_key(self):
        kind = self.key_type_box.currentData()
        if kind == "linear":
            return LinearKey(self.a_spin.value(), self.b_spin.value())
        if kind == "nonlinear":
            return NonlinearKey(self.a_spin.value(), self.b_spin.value(), self.c_spin.value())
        alphabet = TrithemiusCipher(self._lang()).alphabet
        return KeywordKey(self.keyword_edit.text(), alphabet)

    def new_file(self):
        self.editor.clear()
        self.current_path = None
        self.statusBar().showMessage("Новий документ")

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Відкрити файл", "", "Текстові файли (*.txt);;Усі файли (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.editor.setPlainText(f.read())
            self.current_path = path
            self.statusBar().showMessage(f"Відкрито: {path}")
        except (OSError, UnicodeDecodeError) as e:
            QMessageBox.warning(self, "Помилка", f"Не вдалося відкрити файл:\n{e}")

    def save_file(self):
        path = self.current_path
        if not path:
            path, _ = QFileDialog.getSaveFileName(self, "Зберегти файл", "", "Текстові файли (*.txt);;Усі файли (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.editor.toPlainText())
            self.current_path = path
            self.statusBar().showMessage(f"Збережено: {path}")
        except OSError as e:
            QMessageBox.warning(self, "Помилка", f"Не вдалося зберегти файл:\n{e}")

    def print_preview(self):
        doc = QTextDocument()
        doc.setPlainText(self.editor.toPlainText())
        printer = QPrinter()
        dialog = QPrintPreviewDialog(printer, self)
        dialog.paintRequested.connect(doc.print_)
        dialog.exec()

    def encrypt(self):
        self._run_text(encrypt=True)

    def decrypt(self):
        self._run_text(encrypt=False)

    def _run_text(self, encrypt):
        try:
            cipher = TrithemiusCipher(self._lang())
            key = self._build_key()
            text = self.editor.toPlainText()
            result = cipher.encrypt(text, key) if encrypt else cipher.decrypt(text, key)
            self.editor.setPlainText(result)
            self.statusBar().showMessage("Зашифровано" if encrypt else "Розшифровано")
        except CipherError as e:
            QMessageBox.warning(self, "Помилка", str(e))

    def attack(self):
        dialog = AttackDialog(self)
        if dialog.exec() != QDialog.Accepted:
            return
        plain, cipher = dialog.texts()
        if not plain.strip() or not cipher.strip():
            QMessageBox.information(self, "Атака", "Потрібні обидва тексти")
            return
        attacker = KnownPlaintextAttack(self._lang())
        kind = self.key_type_box.currentData()
        try:
            if kind == "linear":
                a, b = attacker.recover_linear(plain, cipher)
                msg = f"Знайдено лінійний ключ: A = {a}, B = {b}"
            elif kind == "nonlinear":
                a, b, c = attacker.recover_nonlinear(plain, cipher)
                msg = f"Знайдено нелінійний ключ: A = {a}, B = {b}, C = {c}"
            else:
                shifts = attacker.recover_keyword_shifts(plain, cipher)
                msg = f"Відновлено послідовність зсувів гасла: {shifts}"
            QMessageBox.information(self, "Результат атаки", msg)
            self.statusBar().showMessage("Ключ відновлено")
        except CipherError as e:
            QMessageBox.warning(self, "Помилка", str(e))

    def about(self):
        QMessageBox.about(
            self, "Про розробника",
            f"Криптосистема на основі шифру Тритеміуса\n\n"
            f"Розробник: {DEVELOPER}\n"
            f"Група: {GROUP}\n"
            f"Практична робота №2\n"
            f"Дисципліна: Безпека програмного забезпечення",
        )


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
