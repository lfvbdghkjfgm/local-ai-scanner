#!/usr/bin/env python3
import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
import pickletools
import hashlib
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
import logging
import numpy as np
import torch
import safetensors
import tensorflow as tf
import keras
from huggingface_hub import HfApi, ModelCard, snapshot_download
import warnings
HAS_TENSORFLOW = True
HAS_HUGGINGFACE = True
HAS_TORCH = True


class Scanner:
    warnings.filterwarnings('ignore', 
                       message='In the future `np.object` will be defined',
                       category=FutureWarning)
    def __init__(self,out_form: str = 'text', verb: bool = False):
        self.out_from = out_form
        self.verb = verb
        self.results = {}
        self.setup_log()

    def setup_log(self):
        logging.basicConfig(
            level=logging.DEBUG if self.verb
            else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def scan(self, path:str, scan_type: str='full') -> Dict[str,Any]:
        self.results = {
            'scan_id':hashlib.sha256(f'{path}{datetime.now()}'.encode()).hexdigest()[:15],
            'timestamp': datetime.now().isoformat(),
            'path':path,
            'scan_type': scan_type,
            'warnings': [],
            'errors': [],
            'recs': []
        }

        try:
            type = self.detect_type(path)
            self.results['model_type'] = type
            self.results['file_info'] = self.file_info(path)

            if scan_type == 'full':
                self.scan_format(path,type)
                self.scan_security(path,type)
            elif scan_type == 'format':
                self.scan_format(path,type)
            elif scan_type == 'security':
                self.scan_security(path,type)
            elif scan_type == 'backdoor':
                self.scan_backdoor(path,type)

            self.calculate_risk()

        except Exception as e:
            self.results['errors'].append(f"Scanning failed: {str(e)}")
            self.logger.error(f"Scanning failed: {e}")

        return self.results

    def detect_type(self,in_path:str) -> str:
        path = Path(in_path)

        if '/' in in_path and not path.exists():
            return "huggingface"
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {in_path}")

        exts  = path.suffix.lower()
        type_mappping = {
            '.pkl': 'pickle',
            '.pickle': 'pickle',
            '.pt': 'pytorch',
            '.pth': 'pytorch',
            '.h5': 'keras',
            '.keras': 'keras',
            '.hdf5': 'keras',
            '.safetensors': 'safetensors',
            '.onnx': 'onnx',
            '.pb': 'tensorflow',
            '.zip': 'zip_archive'
        }
        return type_mappping.get(exts,'unknown')

    def file_info(self,in_path:str) -> Dict[str,Any]:
        path = Path(in_path)
        if not path.exists():
            return {}

        stat = path.stat()
        with open(in_path,'rb') as f:
            hsh = hashlib.sha256(f.read()).hexdigest()

        return {
            'file_size': stat.st_size,
            'file_size_mb': round(stat.st_size / (1024**2),2),
            'mod_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'sha256':hsh
        }

    def scan_format(self,in_path:str,type:str): #сканирование типа ии на опасность
        format_risk = {
            "pickle": "HIGH",
            "pytorch": "MEDIUM",
            "keras": "MEDIUM",
            "safetensors": "LOW",
            "onnx": "LOW",
            "tensorflow": "MEDIUM",
            "huggingface": "VARIABLE"
        }

        risk = format_risk.get(type,'UNKNOWN')
        self.results['format_risk'] = risk

        if risk == 'HIGH':
            self.results['warnings'].append(f"Формат {type} имеет ВЫСОКИЙ риск безопасности")
            self.results["recommendations"].append(f"Рассмотрите конвертацию формата {type} в безопасный формат (safetensors, onnx)")

        if type == "pickle":
            self.scan_pickle(in_path)
        elif type == 'keras':
            self.scan_keras(in_path)
        elif type == "pytorch":
            self.scan_pytorch(in_path)
        elif type == "safetensors":
            self.scan_safet(in_path)
        elif type == "huggingface":
            self.scan_hugging(in_path)

    def scan_pickle(self,path:str):
        self.logger.info('Анализ Pickle файла...')

        try:
            with open(path,'rb') as f:
                data = f.read()

            dangerous_ops = ['GLOBAL', 'REDUCE', 'BUILD', 'INST', 'OBJ']
            susp_ops = []
            for op in pickletools.genops(data):
                opcode = op[0]
                op_name = opcode.name
                arg = op[1] if op[1] else ""

                if op_name in dangerous_ops:
                    susp_ops.append({
                        'opcode': op_name,
                        'argument': str(arg),
                        'position': op[2]
                    })

                if any(keyword in str(arg).lower() for keyword in
                       ['eval', 'exec', 'compile', 'open', 'file', 'system', 'os.', 'subprocess']):
                    self.results["warnings"].append(
                        f"Обнаружен опасный вызов в pickle: {op_name}({arg})"
                    )
            self.results["pickle_analysis"] = {
                "suspicious_operations": susp_ops,
                "total_operations": len(list(pickletools.genops(data)))
            }
            if susp_ops:
                self.results["warnings"].append(
                    f"Обнаружено {len(susp_ops)} подозрительных операций в pickle файле"
                )

        except Exception as e:
            self.results["errors"].append(f"Ошибка анализа pickle: {str(e)}")

    def scan_keras(self,path:str):
        if not HAS_TENSORFLOW:
            self.results["errors"].append("TensorFlow не установлен для анализа Keras моделей")
            return

        try:

            model = tf.keras.models.load_model(path,compile=False)
            lambda_layers = []
            custom_layers = []

            for a,layer in enumerate(model.layers):

                layer_type = type(layer).__name__

                if 'lambda' in layer_type.lower():
                    lambda_layers.append({
                        'index': a,
                        'name': layer.name,
                        'type': layer_type,
                        'config': str(layer.get_config())[:200]
                    })

                elif 'custom' in layer_type.lower() or layer_type not in ['Dense', 'Conv2D', 'LSTM']:
                    custom_layers.append({
                        'index': a,
                        'name': layer.name,
                        'type': layer_type
                    })

            self.results['keras_analysis'] = {
            "total_layers": len(model.layers),
            "lambda_layers": lambda_layers,
            "custom_layers": custom_layers
            }

            if lambda_layers:
                self.results["warnings"].append(
                    f"Обнаружено {len(lambda_layers)} Lambda-слоев, которые могут содержать произвольный код"
                )

            if custom_layers:
                self.results["warnings"].append(
                    f"Обнаружено {len(custom_layers)} кастомных слоев, требующих проверки"
                )

        except Exception as e:
            self.results["errors"].append(f"Ошибка загрузки Keras модели: {str(e)}")

    def scan_pytorch(self,path:str):
        if not HAS_TORCH:
            self.results["errors"].append("PyTorch не установлен для анализа .pt файлов")
            return
        try:
            try:
                data = torch.load(path, map_location='cpu', weights_only=True)
            except:
                self.results["warnings"].append(
                    "Модель содержит небезопасные данные. Используйте weights_only=True для безопасной загрузки."
                )
                return
            info = {
                "loaded_successfully": True,
                "model_type": type(data).__name__ if hasattr(data, '__class__') else "unknown"
            }
            if isinstance(data,dict):
                info["is_state_dict"] = True
                info["keys"] = list(data.keys())[:20]
                info["total_parameters"] = len(data.keys())
            else:
                info["is_state_dict"] = False

            self.results["pytorch_analysis"] = info

        except Exception as e:
            self.results["errors"].append(f"Ошибка загрузки PyTorch модели: {str(e)}")

    def scan_safet(self,path:str):
        try:
            with safetensors.safe_open(path, framework="pt") as f:
                metadata = f.metadata()
                keys = f.keys()
            self.results["safetensors_analysis"] = {
                "tensors_count": len(keys),
                "metadata": metadata,
                "safe_format": True
            }
            self.results["recs"].append(
                "Модель в безопасном формате safetensors - отлично!"
            )
        except Exception as e:
            self.results["errors"].append(f"Ошибка чтения safetensors: {str(e)}")

    def scan_hugging(self,path:str):
        if not HAS_HUGGINGFACE:
            self.results["errors"].append("huggingface_hub не установлен")
            return
        try:
            api = HfApi()
            info = api.model_info(path)

            hf_analys = {
                "model_id": path,
                "downloads": info.downloads,
                "last_modified": info.lastModified.isoformat(),
                "tags": info.tags,
                "siblings": [sibling.rfilename for sibling in info.siblings]
            }

            safe_formats = [s for s in hf_analys["siblings"] if s.endswith('.safetensors')]
            unsafe_formats = [s for s in hf_analys["siblings"] if s.endswith(('.bin', '.pkl'))]

            hf_analys["safe_format_files"] = safe_formats
            hf_analys["unsafe_format_files"] = unsafe_formats

            if safe_formats:
                hf_analys["recommendation"] = "Используйте файлы .safetensors"
            elif unsafe_formats:
                hf_analys["warning"] = "Модель содержит небезопасные форматы файлов"

            self.results["huggingface_analysis"] = hf_analys


        except Exception as e:
            self.results["errors"].append(f"Ошибка получения информации о модели HF: {str(e)}")

    def scan_security(self,path:str,type:str):
        issues = []

        self.check_file_security(path,type,issues)
        self.check_network_capabilities(path,type,issues)
        self.check_system_access(path,type,issues)
        self.check_known_vulnerabilities(path,type,issues)

        self.results['security_issues'] = issues

    def check_file_security(self,path:str,type:str,issues:list):
        if type == "huggingface":
            return

        path = Path(path)

        if not path.exists():
            return

        file_size_mb = self.results.get("file_info", {}).get("file_size_mb", 0)
        if file_size_mb > 2000:
            issues.append(
                f"Подозрительно большой размер модели ({file_size_mb} MB) - возможна упаковка вредоносного кода")
        if type == "zip_archive":
            issues.append("Модель в формате ZIP-архива - требует дополнительной проверки содержимого")
        try:
            if path.stat().st_mode & 0o777 != 0o644:
                issues.append("Нетипичные разрешения файла модели")
        except:
            pass

    def check_network_capabilities(self, model_path: str, model_type: str, issues: list):
        if model_type == "pickle":
            try:
                with open(model_path, 'rb') as f:
                    data = f.read()

                network_keywords = ['http', 'https', 'ftp', 'socket', 'request', 'urlopen', 'connect']
                for op in pickletools.genops(data):
                    arg_str = str(op[1]).lower()
                    if any(keyword in arg_str for keyword in network_keywords):
                        issues.append(f"Обнаружены сетевые операции в модели: {arg_str}")
                        break

            except Exception as e:
                self.logger.debug(f"Ошибка анализа сетевых возможностей: {e}")

        if model_type == "keras" and HAS_TENSORFLOW:
            try:
                model = tf.keras.models.load_model(model_path, compile=False)
                for layer in model.layers:
                    config = layer.get_config()
                    config_str = str(config).lower()
                    if any(keyword in config_str for keyword in ['url', 'http', 'request']):
                        issues.append(f"Слой {layer.name} содержит ссылки на сетевые ресурсы")
            except Exception as e:
                self.logger.debug(f"Ошибка анализа сетевых возможностей Keras: {e}")

    def check_system_access(self, model_path: str, model_type: str, issues: list):

        dangerous_keywords = [
            'os.', 'subprocess', 'sys.', 'shutil', 'open(', 'file(', 'eval', 'exec',
            'compile', 'import', '__import__', 'getattr', 'setattr', 'delattr'
        ]

        if model_type == "pickle":
            try:
                with open(model_path, 'rb') as f:
                    data = f.read()

                for op in pickletools.genops(data):
                    arg_str = str(op[1])
                    for keyword in dangerous_keywords:
                        if keyword in arg_str:
                            issues.append(f"Обнаружены опасные системные вызовы: {arg_str}")
                            break
            except Exception as e:
                self.logger.debug(f"Ошибка анализа системных вызовов: {e}")

    def check_known_vulnerabilities(self, model_path: str, model_type: str, issues: list):

        if model_type == "huggingface":
            return

        known_trojan_signatures = [
            "reverse_shell", "bind_shell", "web_delivery",
            "meterpreter", "beacon", "cobalt_strike"
        ]

        try:
            with open(model_path, 'rb') as f:
                content = f.read().decode('latin-1', errors='ignore').lower()

            for signature in known_trojan_signatures:
                if signature in content:
                    issues.append(f"Обнаружена сигнатура известного трояна: {signature}")

        except Exception as e:
            self.logger.debug(f"Ошибка проверки сигнатур: {e}")

    def scan_backdoor(self,path:str,type:str):
        backdoors_results = {
            "performed_checks": [],
            "suspicious_patterns": [],
            "recommendations": [],
            "advanced_analysis_required": True
        }
        self.check_trigger_patterns(path, type, backdoors_results)
        self.check_anomalous_behavior(path, type, backdoors_results)
        self.check_model_integrity(path, type, backdoors_results)
        self.check_training_data_anomalies(path, type, backdoors_results)


        self.results['backdoor_analysis'] = backdoors_results

        if backdoors_results["suspicious_patterns"]:
            self.results["warnings"].extend(backdoors_results["suspicious_patterns"])

        if backdoors_results["recommendations"]:
            self.results["recommendations"].extend(backdoors_results["recommendations"])

    def check_trigger_patterns(self, model_path: str, model_type: str, backdoor_checks: dict):

        backdoor_checks["performed_checks"].append("trigger_patterns")
        try:
            if model_type == "pytorch" and HAS_TORCH:
                try:
                    model_data = torch.load(model_path, map_location='cpu', weights_only=True)
                except:
                    backdoor_checks["suspicious_patterns"].append(
                        "Не удалось безопасно загрузить модель для анализа тензоров"
                    )
                    return

                if isinstance(model_data, dict):
                    analyzed_tensors = 0
                    for key, tensor in model_data.items():
                        if isinstance(tensor, torch.Tensor) and analyzed_tensors < 5:
                            self.analyze_tensor_anomalies(tensor, key, backdoor_checks)
                            analyzed_tensors += 1

            elif model_type == "keras" and HAS_TENSORFLOW:
                try:
                    model = tf.keras.models.load_model(model_path, compile=False)
                    analyzed_layers = 0
                    for layer in model.layers:
                        weights = layer.get_weights()
                        for i, weight in enumerate(weights):
                            if hasattr(weight, 'shape') and analyzed_layers < 3:
                                if len(weight.shape) > 1 and weight.shape[-1] > 1000:
                                    backdoor_checks["suspicious_patterns"].append(
                                        f"Слой {layer.name} имеет подозрительно большую размерность: {weight.shape}"
                                    )
                                analyzed_layers += 1
                                if analyzed_layers >= 3:
                                    break
                        if analyzed_layers >= 3:
                            break
                except Exception as e:
                    self.logger.debug(f"Ошибка анализа Keras весов: {e}")

        except Exception as e:
            self.logger.debug(f"Ошибка анализа паттернов триггеров: {e}")

    def analyze_tensor_anomalies(self, tensor: torch.Tensor, key: str, backdoor_checks: dict):

        try:
            if tensor.device.type != 'cpu':
                tensor = tensor.cpu()
            tensor_np = tensor.numpy()
            if tensor_np.size > 0:
                flat_tensor = tensor_np.flatten()
                abs_tensor = np.abs(flat_tensor)
                if len(abs_tensor) > 0:
                    extreme_threshold = np.percentile(abs_tensor, 99.9)
                    extreme_count = np.sum(abs_tensor > extreme_threshold)

                    if extreme_count > max(10, tensor_np.size * 0.001):
                        backdoor_checks["suspicious_patterns"].append(
                            f"Обнаружены экстремальные значения в весах {key}: {extreme_count} выбросов"
                        )

                    # Проверка на паттерны (повторяющиеся значения)
                    unique, counts = np.unique(flat_tensor, return_counts=True)
                    if len(unique) < min(100, tensor_np.size * 0.1):
                        backdoor_checks["suspicious_patterns"].append(
                            f"Подозрительно мало уникальных значений в {key}: {len(unique)}"
                        )

        except Exception as e:
            self.logger.debug(f"Ошибка анализа тензора {key}: {e}")

    def check_anomalous_behavior(self, model_path: str, model_type: str, backdoor_checks: dict):

        backdoor_checks["performed_checks"].append("anomalous_behavior")
        if model_type in ["keras", "pytorch"] and self.is_computer_vision_model(model_path, model_type):
            backdoor_checks["suspicious_patterns"].append(
                "Модель компьютерного зрения - рекомендуется тестирование с патчами-триггерами"
            )
            backdoor_checks["recommendations"].append(
                "Проведите тестирование модели на чувствительность к патчам-триггерам"
            )

    def is_computer_vision_model(self, model_path: str, model_type: str) -> bool:
        vision_keywords = ['conv', 'conv2d', 'convolution', 'cnn', 'resnet', 'vgg',
                           'mobilenet', 'efficientnet', 'vision', 'image']

        try:
            if model_type == "keras" and HAS_TENSORFLOW:
                model = tf.keras.models.load_model(model_path, compile=False)
                model_summary = []
                model.summary(print_fn=lambda x: model_summary.append(x))
                model_str = " ".join(model_summary).lower()

                return any(keyword in model_str for keyword in vision_keywords)

            elif model_type == "pytorch" and HAS_TORCH:
                try:
                    model_data = torch.load(model_path, map_location='cpu', weights_only=True)
                    if isinstance(model_data, dict):
                        keys_str = " ".join(model_data.keys()).lower()
                        return any(keyword in keys_str for keyword in vision_keywords)
                except:
                    return False

        except Exception as e:
            self.logger.debug(f"Ошибка определения типа модели CV: {e}")

        return False

    def check_model_integrity(self, model_path: str, model_type: str, backdoor_checks: dict):

        backdoor_checks["performed_checks"].append("model_integrity")
        if model_type == "huggingface":
            backdoor_checks["recommendations"].append(
                "Проверьте цифровую подпись модели на HuggingFace Hub"
            )
        if model_type != "huggingface":
            file_info = self.results.get("file_info", {})
            if file_info.get("sha256"):
                backdoor_checks["file_integrity"] = {
                    "sha256": file_info["sha256"],
                    "verified": "UNKNOWN"
                }

    def check_training_data_anomalies(self, model_path: str, model_type: str, backdoor_checks: dict):

        backdoor_checks["performed_checks"].append("training_data_anomalies")
        if model_type == "huggingface":
            hf_analysis = self.results.get("huggingface_analysis", {})
            tags = hf_analysis.get("tags", [])

            suspicious_tags = ["exclude_from_train", "toxic", "unsafe", "malicious"]
            found_suspicious_tags = [tag for tag in tags if tag in suspicious_tags]

            if found_suspicious_tags:
                backdoor_checks["suspicious_patterns"].append(
                    f"Модель имеет подозрительные теги в метаданных: {found_suspicious_tags}"
                )

    def calculate_risk(self):
        risk = 0
        warnings_count = len(self.results.get('warnings',[]))
        errors_count = len(self.results.get('errors',[]))
        format_risk = self.results.get('format_risk', 'UNKNOWN')

        format_scores = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 2}
        risk += format_scores.get(format_risk, 2)

        security = self.results.get('security_issues',[])
        risk+=min(len(security)*0.7,5)

        bask_analys = self.results.get('backdoor_analysis',{})
        susp_pattern = bask_analys.get('suspicious_patterns',[])
        risk+=min(len(susp_pattern)*0.8,4)

        critical = 0
        for warn in self.results.get('warnings',[]):
            if any(keyword in warn.lower() for keyword in
                   ['reverse_shell', 'trojan', 'backdoor', 'eval', 'exec', 'os.']):
                    critical += 0.5
        risk+=min(critical,2)
        if risk>=6:
            risk_level = 'CRITICAL'
        elif risk>=4:
            risk_level = 'HIGH'
        elif risk>=2:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        self.results["risk_assessment"] = {
            "score": round(risk, 2),
            "level": risk_level,
            "warnings_count": warnings_count,
            "errors_count": errors_count,
            "security_issues_count": len(security),
            "backdoor_suspicions_count": len(susp_pattern),
            "breakdown": {
                "Угрозы формата": format_scores.get(format_risk, 0),
                "Угрозы безопасности": min(len(security) * 0.7, 5),
                "Паттерны бэкдоров": min(len(susp_pattern) * 0.8, 4),
                "Критические угрозы": min(critical, 2)
            }
        }
