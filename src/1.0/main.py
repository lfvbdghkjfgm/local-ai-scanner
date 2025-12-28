#!/usr/bin/env python3

from scanner import Scanner
from output import Outputer
import argparse
import sys
import warnings

def scanning_start_style():
    print("\n" + "─" * 50)
    print(f"     {'>' * 3}  СКАНИРОВАНИЕ НАЧАЛОСЬ  {'<' * 3}")
    print("─" * 50 + "\n")


def main():
    warnings.filterwarnings('ignore', 
                       message='In the future `np.object` will be defined',
                       category=FutureWarning)
    parser = argparse.ArgumentParser(
        description='Local AI Scaner - Сканер ML-моделей на наличие троянов и бэкдоров',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
    Примеры использования:
      %(prog)s model.pkl
      %(prog)s --scan-type full model.h5
      %(prog)s --output-format json model.h5
      %(prog)s --scan-type security --output-file report.json model.pt
      %(prog)s --verbose "username/suspicious-model"
            """
    )
    parser.add_argument('model', help='Путь к модели или идентификатор HuggingFace')
    parser.add_argument('--scan-type', choices=['full', 'format', 'security', 'backdoor'],
                        default='full', help='Тип сканирования (по умолчанию: full)')
    parser.add_argument('--output-format', '-f', choices=['text', 'json', 'csv'],
                        default='text', help='Формат вывода (по умолчанию: text)')
    parser.add_argument('--output-file', '-o', help='Файл для сохранения результатов')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Подробный вывод')

    args = parser.parse_args()
    scanning_start_style()

    scanner = Scanner(out_form=args.output_format, verb=args.verbose)
    results = scanner.scan(args.model, args.scan_type)

    formatter = Outputer()
    if args.output_format == 'json':
        output = formatter.json_format(results)
    elif args.output_format == 'csv':
        output = formatter.csv_format(results)
    else:
        output = formatter.text_format(results)

    if args.output_file:
        with open(args.output_file, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Результаты сохранены в: {args.output_file}")
    else:
        print(output)

    risk_level = results.get('risk_assessment', {}).get('level', 'UNKNOWN')
    if risk_level in ['CRITICAL', 'HIGH']:
        sys.exit(1)
    elif risk_level == 'MEDIUM':
        sys.exit(2)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()



