import os
import base64
import hashlib
import json
import logging
import struct
import time
from typing import Any, Dict, Optional, Union, List, Tuple
from datetime import datetime, timezone
import secrets
import threading
from functools import wraps

from django.db import models, transaction
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.cache import cache
from django.utils.functional import cached_property

# إعداد نظام السجلات
logger = logging.getLogger('medical_encryption')

# ثوابت التشفير المحسنة
ENCRYPTED_PREFIX = "MENC_"  # Medical Encryption prefix
SALT_LENGTH = 32  # زيادة طول المفتاح الملحي
KEY_LENGTH = 32
ITERATION_COUNT = 210000  # تحسين عدد التكرارات
VERSION_BYTE = b'\x01'  # إصدار التشفير للتوافق المستقبلي

# ثوابت HIPAA
HIPAA_AUDIT_ACTIONS = {
    'CREATE': 'Data Created',
    'READ': 'Data Accessed', 
    'UPDATE': 'Data Modified',
    'DELETE': 'Data Deleted',
    'DECRYPT': 'Data Decrypted',
    'ENCRYPT': 'Data Encrypted',
    'KEY_ROTATION': 'Encryption Key Rotated',
    'BULK_ENCRYPT': 'Bulk Encryption Performed'
}

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    logger.error("Cryptography library not available. This is required for HIPAA compliance.")
    CRYPTOGRAPHY_AVAILABLE = False
    raise ImproperlyConfigured("cryptography library is required for medical data encryption")


class SecureKeyManager:
    """
    مدير مفاتيح التشفير الآمن المحسن
    Enhanced Secure Encryption Key Manager
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if not getattr(self, '_initialized', False):
            self._key_cache = {}
            self._master_key = None
            self._salt_cache = {}
            self._initialized = True
            self._initialize_master_key()
    
    def _initialize_master_key(self):
        """تهيئة المفتاح الرئيسي مع دعم عدم تهيئة إعدادات Django"""
        master_key_env = os.getenv('MEDICAL_MASTER_KEY')
        if master_key_env:
            try:
                self._master_key = base64.urlsafe_b64decode(master_key_env.encode())
                return
            except Exception:
                logger.warning("Failed to decode MEDICAL_MASTER_KEY env var; falling back to derived key")

        # محاولة استخدام SECRET_KEY إن كانت إعدادات Django مهيأة، وإلا استخدام قيمة افتراضية آمنة
        secret_key: Optional[str] = None
        try:
            if getattr(settings, 'configured', False):
                secret_key = getattr(settings, 'SECRET_KEY', None)
        except Exception:
            secret_key = None

        secret_key = secret_key or os.getenv('DJANGO_SECRET_KEY') or 'default-medical-key'

        # إضافة معرف فريد للتطبيق الطبي
        app_salt = b'medical_hospital_system_2025'
        combined = f"{secret_key}_medical_encryption".encode() + app_salt
        self._master_key = hashlib.pbkdf2_hmac('sha256', combined, app_salt, ITERATION_COUNT)[:KEY_LENGTH]
    
    def generate_user_key(self, user_id: int, key_version: int = 1) -> bytes:
        """توليد مفتاح مخصص للمستخدم"""
        cache_key = f"user_key_{user_id}_{key_version}"
        
        if cache_key in self._key_cache:
            return self._key_cache[cache_key]
        
        # التأكد من وجود المفتاح الرئيسي
        if self._master_key is None:
            self._initialize_master_key()
        
        # التأكد من أن master_key ليس None بعد التهيئة
        if self._master_key is None:
            raise ValueError("Failed to initialize master key")
        
        # إنشاء مفتاح فريد للمستخدم
        user_data = f"user_{user_id}_v{key_version}".encode()
        user_salt = hashlib.sha256(user_data + self._master_key).digest()[:SALT_LENGTH]
        
        user_key = hashlib.pbkdf2_hmac(
            'sha256',
            self._master_key + user_data,
            user_salt,
            ITERATION_COUNT
        )[:KEY_LENGTH]
        
        self._key_cache[cache_key] = user_key
        return user_key
    
    def generate_field_salt(self, user_id: int, field_name: str, record_id: Optional[str] = None) -> bytes:
        """توليد salt فريد لكل حقل"""
        if self._master_key is None:
            self._initialize_master_key()
        
        # التأكد من أن master_key ليس None بعد التهيئة
        if self._master_key is None:
            raise ValueError("Failed to initialize master key")
            
        salt_data = f"{user_id}_{field_name}_{record_id or 'default'}".encode()
        return hashlib.sha256(salt_data + self._master_key).digest()[:SALT_LENGTH]
    
    def rotate_user_keys(self, user_id: int) -> Tuple[bytes, bytes]:
        """تدوير مفاتيح المستخدم"""
        old_key = self.generate_user_key(user_id, 1)
        new_key = self.generate_user_key(user_id, 2)
        
        # مسح ذاكرة التخزين المؤقت للمفاتيح القديمة
        cache_keys_to_remove = [k for k in list(self._key_cache.keys()) if f"user_{user_id}_" in k]
        for key in cache_keys_to_remove:
            del self._key_cache[key]
        
        return old_key, new_key
    
    @staticmethod
    def generate_master_key() -> str:
        """توليد مفتاح رئيسي جديد للنظام"""
        return base64.urlsafe_b64encode(secrets.token_bytes(KEY_LENGTH)).decode('utf-8')


class AdvancedMedicalEncryption:
    """
    فئة التشفير الطبي المتطورة والمحسنة
    Advanced Medical Data Encryption Class - Enhanced Version
    """
    
    def __init__(self, user_id: Optional[int] = None, custom_key: Optional[bytes] = None):
        self.user_id = user_id
        self.key_manager = SecureKeyManager()
        self.custom_key = custom_key
        self._encryption_key = None
        self._fernet = None
        self._initialize_encryption()
    
    def _initialize_encryption(self):
        """تهيئة نظام التشفير المحسن"""
        try:
            if self.custom_key:
                self._encryption_key = self.custom_key
            elif self.user_id:
                self._encryption_key = self.key_manager.generate_user_key(self.user_id)
            else:
                # استخدام المفتاح الرئيسي للنظام
                if self.key_manager._master_key is None:
                    self.key_manager._initialize_master_key()
                self._encryption_key = self.key_manager._master_key
            
            # التأكد من وجود المفتاح
            if self._encryption_key is None:
                raise ValueError("Unable to initialize encryption key")
            
            # إنشاء مفتاح Fernet
            fernet_key = base64.urlsafe_b64encode(self._encryption_key)
            self._fernet = Fernet(fernet_key)
            
        except Exception as e:
            logger.error(f"خطأ في تهيئة التشفير المتقدم: {e}")
            raise ImproperlyConfigured(f"Failed to initialize medical encryption: {e}")
    
    def encrypt_with_metadata(self, data: str, field_name: str, record_id: Optional[str] = None) -> str:
        """تشفير البيانات مع معلومات إضافية للأمان"""
        if not data or self._fernet is None:
            return data
        
        try:
            # إنشاء salt فريد للحقل
            field_salt = self.key_manager.generate_field_salt(
                self.user_id or 0, field_name, record_id
            )
            
            # إضافة timestamp و metadata
            timestamp = int(time.time())
            metadata = {
                'field': field_name,
                'user_id': self.user_id,
                'timestamp': timestamp,
                'version': 1
            }
            
            # تشفير البيانات
            encrypted_data = self._fernet.encrypt(data.encode('utf-8'))
            
            # دمج المعلومات
            combined_data = {
                'data': base64.urlsafe_b64encode(encrypted_data).decode('utf-8'),
                'salt': base64.urlsafe_b64encode(field_salt).decode('utf-8'),
                'meta': metadata
            }
            
            # تشفير الحزمة كاملة
            final_encrypted = self._fernet.encrypt(
                json.dumps(combined_data, separators=(',', ':')).encode('utf-8')
            )
            
            return base64.urlsafe_b64encode(final_encrypted).decode('utf-8')
            
        except Exception as e:
            logger.error(f"خطأ في تشفير البيانات المتقدم: {e}")
            return data
    
    def decrypt_with_metadata(self, encrypted_data: str) -> Tuple[str, Dict]:
        """فك تشفير البيانات مع استخراج المعلومات الإضافية"""
        if not encrypted_data or self._fernet is None:
            return encrypted_data, {}
        
        try:
            # فك تشفير الحزمة الخارجية
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted_package = self._fernet.decrypt(encrypted_bytes)
            package_data = json.loads(decrypted_package.decode('utf-8'))
            
            # استخراج البيانات المشفرة والمعلومات
            inner_encrypted = base64.urlsafe_b64decode(package_data['data'].encode('utf-8'))
            metadata = package_data['meta']
            
            # فك تشفير البيانات الفعلية
            decrypted_data = self._fernet.decrypt(inner_encrypted).decode('utf-8')
            
            return decrypted_data, metadata
            
        except Exception as e:
            logger.error(f"خطأ في فك التشفير المتقدم: {e}")
            return encrypted_data, {}
    
    def encrypt_data(self, data: str, field_name: str = "default", record_id: Optional[str] = None) -> str:
        """واجهة مبسطة للتشفير"""
        return self.encrypt_with_metadata(data, field_name, record_id)
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """واجهة مبسطة لفك التشفير"""
        decrypted_data, _ = self.decrypt_with_metadata(encrypted_data)
        return decrypted_data
    
    def bulk_encrypt_field(self, model_class, field_name: str, batch_size: int = 500) -> int:
        """تشفير حقل واحد بشكل جماعي محسن"""
        total_updated = 0
        queryset = model_class.objects.filter(**{f"{field_name}__isnull": False})
        total_records = queryset.count()
        
        logger.info(f"بدء تشفير {total_records} سجل للحقل {field_name}")
        
        for offset in range(0, total_records, batch_size):
            batch = queryset[offset:offset + batch_size]
            
            with transaction.atomic():
                updates = []
                for instance in batch:
                    current_value = getattr(instance, field_name)
                    if current_value and not str(current_value).startswith(ENCRYPTED_PREFIX):
                        encrypted_value = self.encrypt_data(
                            str(current_value), 
                            field_name, 
                            str(instance.pk)
                        )
                        setattr(instance, field_name, f"{ENCRYPTED_PREFIX}{encrypted_value}")
                        updates.append(instance)
                
                if updates:
                    model_class.objects.bulk_update(updates, [field_name], batch_size=batch_size)
                    total_updated += len(updates)
                    
                    # تسجيل عملية التشفير الجماعي
                    logger.info(f"تم تشفير {len(updates)} سجل من {field_name}")
        
        return total_updated


class HIPAAAuditLogger:
    """
    مسجل التدقيق المتوافق مع HIPAA
    HIPAA Compliant Audit Logger
    """
    
    @staticmethod
    def log_access(user_id: int, action: str, data_type: str, record_id: Optional[str] = None, 
                   ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> Dict:
        """تسجيل الوصول للبيانات الحساسة"""
        audit_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'user_id': user_id,
            'action': HIPAA_AUDIT_ACTIONS.get(action, action),
            'data_type': data_type,
            'record_id': record_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'compliance_version': '1.0',
            'system_id': 'medical_hospital_system'
        }
        
        logger.info(f"HIPAA_AUDIT: {json.dumps(audit_entry)}")
        return audit_entry
    
    @staticmethod
    def mask_sensitive_data(data: str, data_type: str = 'default', visible_chars: int = 4) -> str:
        """إخفاء البيانات الحساسة وفقاً لمعايير HIPAA"""
        if not data or len(data) <= visible_chars:
            return '*' * len(data) if data else ''
        
        if data_type == 'email' or '@' in data:
            username, domain = data.split('@', 1) if '@' in data else (data, '')
            masked_username = username[:2] + '*' * (len(username) - 2)
            return f"{masked_username}@{domain}" if domain else masked_username
        
        elif data_type == 'phone':
            # إخفاء الأرقام الوسطى من رقم الهاتف
            if len(data) > 8:
                return data[:3] + '*' * (len(data) - 6) + data[-3:]
            return '*' * len(data)
        
        elif data_type == 'id' or data_type == 'ssn':
            # إخفاء معظم الرقم مع الاحتفاظ بآخر 4 أرقام
            return '*' * (len(data) - 4) + data[-4:] if len(data) > 4 else '*' * len(data)
        
        else:
            # إخفاء عام
            return data[:visible_chars] + '*' * (len(data) - visible_chars)


def audit_access(action: str, data_type: str):
    """ديكوريتر لتسجيل الوصول للبيانات"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # محاولة الحصول على معلومات المستخدم من السياق
                user_id = getattr(args[0], 'user_id', None) if args else None
                record_id = kwargs.get('record_id') or (str(args[1]) if len(args) > 1 else None)
                
                # تسجيل العملية
                HIPAAAuditLogger.log_access(
                    user_id=user_id or 0,
                    action=action,
                    data_type=data_type,
                    record_id=record_id
                )
                
                return func(*args, **kwargs)
            except Exception as e:
                logger.error(f"خطأ في تسجيل التدقيق: {e}")
                return func(*args, **kwargs)
        
        return wrapper
    return decorator


# الحقول المشفرة المحسنة مع دعم كامل لـ Django ORM
class BaseEncryptedField(models.Field):
    """
    حقل أساسي مشفر يدعم:
    - Django ORM (objects.get, objects.all, etc.)
    - Django Admin
    - DRF Serializers
    - QuerySets (values, values_list)
    - Template rendering
    """
    
    def __init__(self, user_field=None, encryption_key=None, *args, **kwargs):
        """
        تهيئة الحقل المشفر
        
        Args:
            user_field: اسم الحقل الذي يحتوي على معرف المستخدم
            encryption_key: مفتاح تشفير مخصص (اختياري)
        """
        self.user_field = user_field
        self.encryption_key = encryption_key
        super().__init__(*args, **kwargs)
    
    def contribute_to_class(self, cls, name, **kwargs):
        """إضافة الحقل إلى الفئة مع إعداد خاص للتشفير"""
        super().contribute_to_class(cls, name, **kwargs)
        
        # إضافة خاصية للوصول للقيمة المشفرة الخام
        raw_field_name = f'_{name}_encrypted_raw'
        setattr(cls, raw_field_name, None)
        
        # إضافة خاصية للتحقق من حالة التشفير
        is_encrypted_field_name = f'{name}_is_encrypted'
        setattr(cls, is_encrypted_field_name, property(
            lambda self: is_encrypted(getattr(self, name, '')) if hasattr(self, name) else False
        ))
        
        # إضافة دالة للحصول على القيمة المشفرة
        def get_encrypted_value(instance):
            raw_field = f'_{name}_encrypted_raw'
            if hasattr(instance, raw_field):
                return getattr(instance, raw_field)
            return getattr(instance, name, '')
        
        setattr(cls, f'get_{name}_encrypted', get_encrypted_value)
    
    def pre_save(self, model_instance, add):
        """تشفير القيمة قبل الحفظ"""
        value = getattr(model_instance, self.attname)
        
        if value is None or value == '':
            return value
        
        # إذا كانت القيمة مشفرة بالفعل، لا نحتاج لتشفيرها مرة أخرى
        if isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX):
            return value
        
        # الحصول على معرف المستخدم
        user_id = self._get_user_id(model_instance)
        
        # تشفير القيمة
        try:
            encryptor = AdvancedMedicalEncryption(
                user_id=user_id, 
                custom_key=self.encryption_key
            )
            encrypted_value = encryptor.encrypt_data(str(value), self.attname)
            encrypted_with_prefix = f"{ENCRYPTED_PREFIX}{encrypted_value}"
            
            # حفظ القيمة الخام للوصول المتقدم
            raw_field_name = f'_{self.attname}_encrypted_raw'
            setattr(model_instance, raw_field_name, encrypted_with_prefix)
            
            # تسجيل عملية التشفير
            HIPAAAuditLogger.log_access(
                user_id=user_id,
                action='ENCRYPT',
                data_type=self.attname,
                record_id=str(getattr(model_instance, 'id', 'new'))
            )
            
            return encrypted_with_prefix
            
        except Exception as e:
            logger.error(f"فشل تشفير الحقل {self.attname}: {e}")
            raise ValueError(f"فشل في تشفير البيانات: {e}")
    
    def from_db_value(self, value, expression, connection):
        """فك تشفير القيمة عند الجلب من قاعدة البيانات"""
        if value is None:
            return value
        
        return self._decrypt_value(value, expression)
    
    def to_python(self, value):
        """تحويل القيمة إلى Python object مع فك التشفير"""
        if value is None:
            return value
        
        if isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX):
            return self._decrypt_value(value)
        
        return value
    
    def get_prep_value(self, value):
        """تحضير القيمة للحفظ في قاعدة البيانات"""
        if value is None:
            return value
        
        # إذا كانت القيمة مشفرة بالفعل، نعيدها كما هي
        if isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX):
            return value
        
        # إذا لم تكن مشفرة، نحتاج لتشفيرها
        # لكن هذا سيتم في pre_save
        return value
    
    def value_to_string(self, obj):
        """تحويل القيمة إلى string للتسلسل (Django Admin, DRF)"""
        value = self.value_from_object(obj)
        return '' if value is None else str(value)
    
    def value_from_object(self, obj):
        """استخراج القيمة من الكائن مع فك التشفير"""
        value = getattr(obj, self.attname, self.get_default())
        return self._decrypt_value(value) if value else value
    
    def _get_user_id(self, model_instance):
        """الحصول على معرف المستخدم من النموذج"""
        if self.user_field:
            user_obj = getattr(model_instance, self.user_field, None)
            if user_obj is not None:
                if hasattr(user_obj, 'id'):
                    return user_obj.id
                elif hasattr(user_obj, 'pk'):
                    return user_obj.pk
                elif isinstance(user_obj, (int, str)):
                    return int(user_obj)
        
        # محاولة العثور على معرف المستخدم في الحقول الشائعة
        for field_name in ['user_id', 'created_by_id', 'owner_id', 'doctor_id']:
            if hasattr(model_instance, field_name):
                user_id = getattr(model_instance, field_name)
                if user_id:
                    return user_id
        
        # إذا لم نجد معرف المستخدم، نستخدم معرف النموذج نفسه أو افتراضي
        return getattr(model_instance, 'id', 1) or 1
    
    def _decrypt_value(self, encrypted_value, expression=None):
        """فك تشفير القيمة مع تسجيل التدقيق"""
        if not isinstance(encrypted_value, str) or not encrypted_value.startswith(ENCRYPTED_PREFIX):
            return encrypted_value
        
        try:
            # إزالة البادئة
            clean_encrypted = encrypted_value.replace(ENCRYPTED_PREFIX, '')
            
            # محاولة فك التشفير مع مفاتيح مختلفة
            user_ids_to_try = [1, 2, 3, 4, 5]  # يمكن تحسين هذا بقراءة المستخدمين النشطين
            
            for user_id in user_ids_to_try:
                try:
                    encryptor = AdvancedMedicalEncryption(
                        user_id=user_id,
                        custom_key=self.encryption_key
                    )
                    decrypted = encryptor.decrypt_data(clean_encrypted)
                    
                    # تسجيل عملية فك التشفير
                    HIPAAAuditLogger.log_access(
                        user_id=user_id,
                        action='DECRYPT',
                        data_type=getattr(self, 'attname', 'unknown_field'),
                        record_id='field_access'
                    )
                    
                    return decrypted
                except Exception:
                    continue
            
            # إذا فشل فك التشفير مع جميع المفاتيح
            logger.warning(f"فشل فك تشفير القيمة للحقل {getattr(self, 'attname', 'unknown')}")
            return f"[ENCRYPTED_DATA_ERROR]"
            
        except Exception as e:
            logger.error(f"خطأ في فك تشفير الحقل: {e}")
            return f"[DECRYPTION_ERROR: {str(e)}]"
    
    def get_internal_type(self):
        """نوع الحقل الداخلي - نخزن جميع البيانات المشفرة كـ TextField"""
        return 'TextField'
    
    def formfield(self, **kwargs):
        """إنشاء حقل النموذج المناسب للـ Django Admin"""
        defaults = {}
        if hasattr(self, 'max_length') and self.max_length:
            defaults['max_length'] = self.max_length
        defaults.update(kwargs)
        return super().formfield(**defaults)
    
    def clean(self, value, model_instance):
        """تنظيف وتحقق من صحة القيمة"""
        value = self.to_python(value)
        if model_instance is not None:
            self.validate(value, model_instance)
        self.run_validators(value)
        return value


class EncryptedCharField(BaseEncryptedField):
    """حقل CharField مشفر محسن مع دعم كامل للـ Django ORM"""
    
    def __init__(self, max_length=None, user_field=None, encryption_key=None, *args, **kwargs):
        self.max_length = max_length or 500  # حجم افتراضي للبيانات المشفرة
        super().__init__(user_field=user_field, encryption_key=encryption_key, max_length=self.max_length, *args, **kwargs)
    
    def get_internal_type(self):
        return 'CharField'
    
    def formfield(self, **kwargs):
        """حقل النموذج للـ Django Admin"""
        from django import forms
        defaults = {'max_length': self.max_length}
        defaults.update(kwargs)
        return super().formfield(form_class=forms.CharField, **defaults)


class EncryptedTextField(BaseEncryptedField):
    """حقل TextField مشفر محسن"""
    
    def get_internal_type(self):
        return 'TextField'
    
    def formfield(self, **kwargs):
        from django import forms
        defaults = {'widget': forms.Textarea}
        defaults.update(kwargs)
        return super().formfield(form_class=forms.CharField, **defaults)


class EncryptedEmailField(BaseEncryptedField):
    """حقل البريد الإلكتروني المشفر محسن مع التحقق من صحة الإيميل"""
    
    def __init__(self, max_length=None, user_field=None, encryption_key=None, *args, **kwargs):
        self.max_length = max_length or 500
        super().__init__(user_field=user_field, encryption_key=encryption_key, max_length=self.max_length, *args, **kwargs)
    
    def validate(self, value, model_instance):
        """التحقق من صحة البريد الإلكتروني قبل التشفير"""
        super().validate(value, model_instance)
        if value and value not in [None, '']:
            from django.core.validators import validate_email
            try:
                validate_email(value)
            except Exception as e:
                raise ValueError(f"عنوان البريد الإلكتروني غير صحيح: {e}")
    
    def get_internal_type(self):
        return 'CharField'
    
    def formfield(self, **kwargs):
        from django import forms
        defaults = {'max_length': self.max_length}
        defaults.update(kwargs)
        return super().formfield(form_class=forms.EmailField, **defaults)


class EncryptedPhoneField(BaseEncryptedField):
    """حقل رقم الهاتف المشفر محسن مع التحقق من الصيغة"""
    
    def __init__(self, max_length=None, user_field=None, encryption_key=None, *args, **kwargs):
        self.max_length = max_length or 500
        super().__init__(user_field=user_field, encryption_key=encryption_key, max_length=self.max_length, *args, **kwargs)
    
    def validate(self, value, model_instance):
        """التحقق من صحة رقم الهاتف"""
        super().validate(value, model_instance)
        if value and value not in [None, '']:
            # تحقق بسيط من صيغة رقم الهاتف
            import re
            phone_pattern = r'^[\+]?[1-9][\d\s\-\(\)]{7,15}$'
            if not re.match(phone_pattern, str(value).strip()):
                raise ValueError("صيغة رقم الهاتف غير صحيحة")
    
    def get_internal_type(self):
        return 'CharField'
    
    def formfield(self, **kwargs):
        from django import forms
        defaults = {'max_length': self.max_length}
        defaults.update(kwargs)
        return super().formfield(form_class=forms.CharField, **defaults)


class EncryptedIDField(BaseEncryptedField):
    """حقل الهوية المشفر (رقم هوية، جواز سفر، إلخ)"""
    
    def __init__(self, max_length=None, user_field=None, encryption_key=None, *args, **kwargs):
        self.max_length = max_length or 500
        super().__init__(user_field=user_field, encryption_key=encryption_key, max_length=self.max_length, *args, **kwargs)
    
    def validate(self, value, model_instance):
        """التحقق من صحة رقم الهوية"""
        super().validate(value, model_instance)
        if value and value not in [None, '']:
            # تحقق من أن القيمة تحتوي على أرقام أو حروف فقط
            import re
            id_pattern = r'^[A-Za-z0-9\-]+$'
            if not re.match(id_pattern, str(value).strip()):
                raise ValueError("رقم الهوية يجب أن يحتوي على أرقام وحروف فقط")
    
    def get_internal_type(self):
        return 'CharField'


class EncryptedJSONField(BaseEncryptedField):
    """حقل JSON مشفر للبيانات المعقدة"""
    
    def __init__(self, default=dict, user_field=None, encryption_key=None, *args, **kwargs):
        if callable(default):
            kwargs['default'] = default
        else:
            kwargs['default'] = lambda: default
        super().__init__(user_field=user_field, encryption_key=encryption_key, *args, **kwargs)
    
    def to_python(self, value):
        """تحويل إلى Python object مع فك التشفير وتحليل JSON"""
        if value is None:
            return value
        
        # فك التشفير أولاً
        decrypted_value = super().to_python(value)
        
        # إذا كانت القيمة مفكوكة التشفير، حاول تحليلها كـ JSON
        if isinstance(decrypted_value, str):
            try:
                import json
                return json.loads(decrypted_value)
            except (json.JSONDecodeError, TypeError):
                # إذا فشل تحليل JSON، أعد القيمة كما هي
                return decrypted_value
        
        return decrypted_value
    
    def get_prep_value(self, value):
        """تحضير قيمة JSON للتشفير"""
        if value is None:
            return value
        
        # تحويل إلى JSON أولاً
        if not isinstance(value, str):
            import json
            try:
                value = json.dumps(value, ensure_ascii=False)
            except (TypeError, ValueError) as e:
                raise ValueError(f"لا يمكن تحويل القيمة إلى JSON: {e}")
        
        return super().get_prep_value(value)
    
    def get_internal_type(self):
        return 'TextField'
    
    def formfield(self, **kwargs):
        from django import forms
        defaults = {'widget': forms.Textarea(attrs={'rows': 5})}
        defaults.update(kwargs)
        return super().formfield(form_class=forms.CharField, **defaults)


class EnhancedHIPAACompliance:
    """أدوات الامتثال المحسنة لـ HIPAA"""
    
    @staticmethod
    def mask_sensitive_data(data: str, mask_char: str = '*', visible_chars: int = 4) -> str:
        """إخفاء البيانات الحساسة"""
        return HIPAAAuditLogger.mask_sensitive_data(data, 'default', visible_chars)
    
    @staticmethod
    def create_audit_log(action: str, user_id: int, data_type: str, record_id: Optional[str] = None) -> dict:
        """إنشاء سجل تدقيق"""
        return HIPAAAuditLogger.log_access(user_id, action, data_type, record_id)


class BulkEncryptionUtility:
    """أداة التشفير الجماعي للبيانات الموجودة المحسنة"""
    
    def __init__(self, user_id: Optional[int] = None, encryption_key: Optional[bytes] = None):
        self.encryptor = AdvancedMedicalEncryption(user_id=user_id, custom_key=encryption_key)
    
    def encrypt_model_fields(self, model_class, field_mapping: Dict[str, str], batch_size: int = 1000):
        """تشفير حقول نموذج بشكل جماعي"""
        total_records = model_class.objects.count()
        processed = 0
        
        for offset in range(0, total_records, batch_size):
            batch = model_class.objects.all()[offset:offset + batch_size]
            
            for instance in batch:
                updated = False
                for field_name, field_type in field_mapping.items():
                    current_value = getattr(instance, field_name)
                    if current_value and not str(current_value).startswith(ENCRYPTED_PREFIX):
                        encrypted_value = self.encryptor.encrypt_data(str(current_value), field_name)
                        setattr(instance, field_name, f"{ENCRYPTED_PREFIX}{encrypted_value}")
                        updated = True
                
                if updated:
                    instance.save()
                    processed += 1
        
        return processed


class EncryptionKeyManager:
    """مدير مفاتيح التشفير المحسن"""
    
    @staticmethod
    def generate_key() -> str:
        """توليد مفتاح تشفير جديد"""
        return base64.urlsafe_b64encode(secrets.token_bytes(KEY_LENGTH)).decode('utf-8')
    
    @staticmethod
    def rotate_key(old_key: str, new_key: str, model_class, encrypted_fields: List[str]):
        """تدوير مفتاح التشفير"""
        old_key_bytes = base64.urlsafe_b64decode(old_key.encode()) if isinstance(old_key, str) else old_key
        new_key_bytes = base64.urlsafe_b64decode(new_key.encode()) if isinstance(new_key, str) else new_key
        
        old_encryptor = AdvancedMedicalEncryption(custom_key=old_key_bytes)
        new_encryptor = AdvancedMedicalEncryption(custom_key=new_key_bytes)
        
        for instance in model_class.objects.all():
            updated = False
            for field_name in encrypted_fields:
                encrypted_value = getattr(instance, field_name)
                if encrypted_value and encrypted_value.startswith(ENCRYPTED_PREFIX):
                    # فك التشفير بالمفتاح القديم
                    clean_encrypted = encrypted_value.replace(ENCRYPTED_PREFIX, '')
                    decrypted = old_encryptor.decrypt_data(clean_encrypted)
                    # إعادة التشفير بالمفتاح الجديد
                    re_encrypted = new_encryptor.encrypt_data(decrypted, field_name)
                    setattr(instance, field_name, f"{ENCRYPTED_PREFIX}{re_encrypted}")
                    updated = True
            
            if updated:
                instance.save()


# دوال مساعدة للتشفير السريع محسنة
def quick_encrypt(data: str, key: Optional[str] = None, user_id: Optional[int] = None) -> str:
    """تشفير سريع للبيانات"""
    key_bytes = base64.urlsafe_b64decode(key.encode()) if key else None
    encryptor = AdvancedMedicalEncryption(user_id=user_id, custom_key=key_bytes)
    encrypted = encryptor.encrypt_data(data)
    return f"{ENCRYPTED_PREFIX}{encrypted}"


def quick_decrypt(encrypted_data: str, key: Optional[str] = None, user_id: Optional[int] = None) -> str:
    """فك تشفير سريع للبيانات"""
    key_bytes = base64.urlsafe_b64decode(key.encode()) if key else None
    encryptor = AdvancedMedicalEncryption(user_id=user_id, custom_key=key_bytes)
    
    # إزالة البادئة إذا كانت موجودة
    clean_data = encrypted_data.replace(ENCRYPTED_PREFIX, '') if isinstance(encrypted_data, str) and encrypted_data.startswith(ENCRYPTED_PREFIX) else encrypted_data
    return encryptor.decrypt_data(clean_data)


def is_encrypted(data: str) -> bool:
    """فحص ما إذا كانت البيانات مشفرة"""
    return isinstance(data, str) and data.startswith(ENCRYPTED_PREFIX)


def encrypt_password(password: str, user_id: int) -> str:
    """تشفير كلمة المرور بطريقة آمنة"""
    encryptor = AdvancedMedicalEncryption(user_id=user_id)
    return encryptor.encrypt_data(password, 'password')


def decrypt_password(encrypted_password: str, user_id: int) -> str:
    """فك تشفير كلمة المرور"""
    if not isinstance(encrypted_password, str) or not encrypted_password.startswith(ENCRYPTED_PREFIX):
        return encrypted_password
    
    clean_encrypted = encrypted_password.replace(ENCRYPTED_PREFIX, '')
    encryptor = AdvancedMedicalEncryption(user_id=user_id)
    return encryptor.decrypt_data(clean_encrypted)


# إعداد backward compatibility
MedicalDataEncryption = AdvancedMedicalEncryption
