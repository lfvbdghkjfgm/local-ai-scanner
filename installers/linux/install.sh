#!/bin/bash

echo "Установка ML Security Scanner v1.0.0"
echo "====================================="

# Определяем путь установки
INSTALL_PATH="$HOME/.local/share/ml-scanner"
BIN_PATH="$HOME/.local/bin"

echo "Установка в: $INSTALL_PATH"

# Создаем папки
mkdir -p "$INSTALL_PATH"
mkdir -p "$BIN_PATH"

# Проверяем наличие архива
ARCHIVE_PATH="$(dirname "$0")/../releases/linux/scan-latest.tar.gz"
if [ ! -f "$ARCHIVE_PATH" ]; then
    echo "Ошибка: архив scan-latest.tar.gz не найден"
    echo "Ищите его в: $ARCHIVE_PATH"
    exit 1
fi

# Распаковываем архив
echo "Распаковываю архив..."
tar -xzf "$ARCHIVE_PATH" -C "$INSTALL_PATH"

# Создаем скрипт-обертку в ~/.local/bin
echo "Создаю скрипт запуска..."
cat > "$BIN_PATH/scan" << 'EOF'
#!/bin/bash
SCAN_DIR="$HOME/.local/share/ml-scanner/scan"
"$SCAN_DIR/scan" "$@"
EOF

chmod +x "$BIN_PATH/scan"

# Проверяем, что ~/.local/bin в PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null
    echo "Добавлен ~/.local/bin в PATH"
fi

echo ""
echo "====================================="
echo "Установка завершена!"
echo "1. Перезапустите терминал или выполните: source ~/.bashrc"
echo "2. Используйте команду: scan <путь_к_модели>"
echo "3. Пример: scan ./model.pth --verbose"
echo "====================================="