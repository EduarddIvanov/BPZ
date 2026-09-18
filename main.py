import sys

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QPlainTextEdit, QComboBox, QSpinBox,
    QLabel, QWidget, QVBoxLayout, QHBoxLayout, QMessageBox, QFileDialog,
    QDialog, QListWidget, QDialogButtonBox,
)
from PySide6.QtGui import QAction, QTextDocument
from PySide6.QtPrintSupport import QPrintPreviewDialog, QPrinter

from caesar import CaesarCipher, ByteCaesarCipher, CipherError
from bruteforce import BruteForceAttack

DEVELOPER = "Іванов Едуард Костянтинович"
GROUP = "ТВ-33"


class BruteForceDialog(QDialog):
    def __init__(self, results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Атака грубою силою")
        self.resize(560, 400)
        self.selected = None

        self.list = QListWidget()
        for key, guess, score in results:
            preview = guess[:80].replace("\n", " ")
            self.list.addItem(f"[ключ={key:>3}]  {preview}")
        self._results = results

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Варіанти впорядковані за схожістю на природний текст:"))
        layout.addWidget(self.list)
        layout.addWidget(buttons)
        self.list.setCurrentRow(0)

    def _accept(self):
        row = self.list.currentRow()
        if row >= 0:
            self.selected = self._results[row]
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Шифр Цезаря — криптосистема")
        self.resize(760, 560)
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

        self.key_spin = QSpinBox()
        self.key_spin.setRange(1, 255)
        self.key_spin.setValue(3)

        top = QHBoxLayout()
        top.addWidget(QLabel("Мова:"))
        top.addWidget(self.lang_box)
        top.addSpacing(20)
        top.addWidget(QLabel("Ключ:"))
        top.addWidget(self.key_spin)
        top.addStretch()

        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addWidget(self.editor)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        self.statusBar().showMessage("Готово")

    def _build_actions(self):
        self.act_new = QAction("Створити", self, triggered=self.new_file)
        self.act_open = QAction("Відкрити", self, triggered=self.open_file)
        self.act_save = QAction("Зберегти", self, triggered=self.save_file)
        self.act_print = QAction("Друк (перегляд)", self, triggered=self.print_preview)
        self.act_exit = QAction("Вихід", self, triggered=self.close)

        self.act_encrypt = QAction("Зашифрувати", self, triggered=self.encrypt)
        self.act_decrypt = QAction("Розшифрувати", self, triggered=self.decrypt)
        self.act_attack = QAction("Атака (перебір)", self, triggered=self.brute_force)

        self.act_encrypt_bin = QAction("Зашифрувати файл (будь-який формат)", self,
                                       triggered=lambda: self.process_binary(encrypt=True))
        self.act_decrypt_bin = QAction("Розшифрувати файл (будь-який формат)", self,
                                       triggered=lambda: self.process_binary(encrypt=False))

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
        m_crypto.addSeparator()
        m_crypto.addActions([self.act_encrypt_bin, self.act_decrypt_bin])

        m_help = menubar.addMenu("Довідка")
        m_help.addAction(self.act_about)

    def _build_toolbar(self):
        tb = self.addToolBar("Основне")
        tb.addActions([self.act_new, self.act_open, self.act_save, self.act_print])
        tb.addSeparator()
        tb.addActions([self.act_encrypt, self.act_decrypt, self.act_attack])

    def _lang(self):
        return self.lang_box.currentData()

    def _cipher(self):
        return CaesarCipher(self._lang())

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
            cipher = self._cipher()
            key = self.key_spin.value()
            text = self.editor.toPlainText()
            result = cipher.encrypt(text, key) if encrypt else cipher.decrypt(text, key)
            self.editor.setPlainText(result)
            self.statusBar().showMessage("Зашифровано" if encrypt else "Розшифровано")
        except CipherError as e:
            QMessageBox.warning(self, "Помилка", str(e))

    def brute_force(self):
        text = self.editor.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "Атака", "Спершу введіть або відкрийте зашифрований текст")
            return
        attack = BruteForceAttack(self._lang())
        dialog = BruteForceDialog(attack.attack(text), self)
        if dialog.exec() == QDialog.Accepted and dialog.selected:
            key, guess, _ = dialog.selected
            self.editor.setPlainText(guess)
            self.key_spin.setValue(key)
            self.statusBar().showMessage(f"Підібрано ключ: {key}")

    def process_binary(self, encrypt):
        src, _ = QFileDialog.getOpenFileName(self, "Оберіть файл", "", "Усі файли (*)")
        if not src:
            return
        dst, _ = QFileDialog.getSaveFileName(self, "Зберегти результат", "", "Усі файли (*)")
        if not dst:
            return
        try:
            cipher = ByteCaesarCipher()
            key = self.key_spin.value()
            with open(src, "rb") as f:
                data = f.read()
            result = cipher.encrypt(data, key) if encrypt else cipher.decrypt(data, key)
            with open(dst, "wb") as f:
                f.write(result)
            self.statusBar().showMessage(f"Файл оброблено: {dst}")
        except (OSError, CipherError) as e:
            QMessageBox.warning(self, "Помилка", f"Не вдалося обробити файл:\n{e}")

    def about(self):
        QMessageBox.about(
            self, "Про розробника",
            f"Криптосистема на основі шифру Цезаря\n\n"
            f"Розробник: {DEVELOPER}\n"
            f"Група: {GROUP}\n"
            f"Практична робота №1\n"
            f"Дисципліна: Безпека програмного забезпечення",
        )


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
