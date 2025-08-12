<div align="center">

# 🌀 **NucleiHarvest**

**Fast and organized Nuclei templates harvester for security researchers and bug bounty hunters.**

**Developer:** **mon3im.officeil (MX8)**

<!-- After you create the repo on GitHub, replace USER/REPO below to activate live badges -->

<p>
  <img src="https://img.shields.io/badge/Python-%3E%3D3.10-blue" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT"/>
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs welcome"/>
  <img src="https://img.shields.io/badge/Style-black-000000?logo=ruff&logoColor=white" alt="ruff"/>
</p>

> يجلب **NucleiHarvest** قوالب [Nuclei](https://github.com/projectdiscovery/nuclei) من مستودعات متعددة، يزيل التكرار، ويعيد تنظيمها في بنية مرتبة وجاهزة للاستخدام.

</div>

---

## 🗺️ فهرس المحتويات (Table of Contents)

* [المميزات](#-features)
* [البدء السريع](#-quick-start)
* [خيارات CLI](#%EF%B8%8F-cli-options-%D9%85%D9%84%D8%AE%D8%B5)
* [هيكل الإخراج](#-output-structure)
* [أمثلة](#-examples)
* [للمطورين](#-development)
* [خارطة الطريق](#%EF%B8%8F-roadmap-%D8%A7%D8%AE%D8%AA%D9%8A%D8%A7%D8%B1%D9%8A)
* [المساهمة](#-contributing)
* [الترخيص](#-license)
* [الشكر](#-acknowledgements)

---

## ✨ Features

<div align="center">

| ⚙️ ميزة         | 💡 الوصف                                                                                 |
| --------------- | ---------------------------------------------------------------------------------------- |
| تخزين ذكي       | يكتشف تلقائيًا أكبر قسم قرص متاح للكتابة ويستخدمه للتخزين المؤقت والملفات المؤقتة        |
| جلب مرن         | يجلب القوالب عبر `git` أو GitHub API أو تنزيل ZIP عند الحاجة                             |
| إزالة التكرار   | يعتمد بصمة **SHA‑1** لتخزين YAML الفريد داخل `.store/` مع **hard‑links** للبنية النهائية |
| الاستئناف الآمن | يكمل بعد الانقطاع، مع سجل تفصيلي في `run.log`                                            |
| وقف آمن         | يتوقف بأمان عند انخفاض المساحة أو ضغط **Ctrl+C**                                         |
| واجهة غنية      | عرض حالة كل مستودع وعدّادات مباشرة                                                       |

</div>

> **Why?** بدلًا من متابعة عشرات المستودعات يدويًا، اجمع كل شيء في مكان واحد بسرعة وبنية واضحة.


<img width="1580" height="576" alt="2PNG" src="https://github.com/user-attachments/assets/228418ce-1c5b-4a92-be9f-3ceb65554f86" />
<img width="1569" height="331" alt="image" src="https://github.com/user-attachments/assets/df56a711-af47-4c8a-a976-b042bc3dd775" />


---

## 🚀 Quick Start

### 1) المتطلبات

* Python **3.10+**
* تثبيت الاعتمادات:

```bash
pip install -r requirements.txt
```

### 2) التشغيل السريع

إذا كنت تستخدم نفس ملف السكربت الأصلي:

```bash
python MX8_TMPLT.py
```

> **بديل مفضل:** أعد تسمية الملف إلى `nuclei_harvest.py` ثم:

```bash
python nuclei_harvest.py
```

### 3) المساعدة

```bash
python MX8_TMPLT.py -h
```

---

## 🧰️ CLI Options (ملخص)

<details>
<summary><strong>انقر لعرض أهم الخيارات</strong></summary>

* `--repo-list-url <url>`: رابط لملف نصي يحوي عناوين المستودعات (واحد في كل سطر).
* `--output-dir <dir>`: مجلد الإخراج حيث تُخزَّن القوالب والبيانات (افتراضي: `Templates`).
* `--temp-dir <dir>`: مجلد للتخزين المؤقت والملفات المؤقتة (يتجاوز اختيار القسم التلقائي).
* `--search <term>`: البحث السريع داخل القوالب المجمعة ثم الخروج.
* `--save-success-list <file>`: حفظ قائمة بالمستودعات التي تم جلبها بنجاح.
* `--save-templates <archive.zip>`: إنشاء أرشيف ZIP لكل القوالب المجمعة.
* `--setup` / `--reset-config` / `--yes`: إعداد تفاعلي، إعادة ضبط الإعدادات، أو تشغيل غير تفاعلي بالافتراضيات.

</details>

---

## 📂 Output Structure

```
.store/               # YAML blobs فريدة مُسماة حسب SHA‑1
Templates/            # البنية الأساسية (CVE/<year>/... أو protocol/severity/vendor/product/...)
Indexes/              # فهارس ثانوية عبر hard‑links حسب الشدة/النوع/المورّد/المنتج/الوسوم
manifest.json         # حالة كل مستودع (مُحدّث، مُتخطى، فشل، ...)
content-index.json    # ميتاداتا لكل SHA‑1 فريد
run.log               # سجل زمني مفصّل لتتبُّع المشاكل
```

---

## 🧪 Examples

اجلب القوالب إلى مجلد مخصص، ثم أنشئ أرشيفًا:

```bash
python MX8_TMPLT.py --output-dir Templates --save-templates nuclei-templates.zip
```

ابحث عن كلمة مفتاحية داخل المحتوى المُجمّع:

```bash
python MX8_TMPLT.py --search wordpress
```

استخدم ملف روابط مستودعات مخصص:

```bash
python MX8_TMPLT.py --repo-list-url https://example.com/nuclei_repos.txt
```

---

## 🧑‍💻 Development

* يُنصح باستخدام بيئة افتراضية:

```bash
python -m venv .venv
source .venv/bin/activate  # أو .venv\Scripts\activate على Windows
pip install -r requirements.txt
```

* تنسيق الكود وفحصه (اختياري):

```bash
python -m pip install ruff pytest
ruff check .
pytest -q
```

---

## 🗺️ Roadmap (اختياري)

* [ ] واجهة أوامر مختصرة باسم `nuharvest`.
* [ ] دمج مصادر إضافية خارج GitHub.
* [ ] مؤشرات تقدم أكثر تفصيلاً وإحصاءات بعد كل تشغيل.
* [ ] دعم حفظ لقطات إصدار (Releases) أسبوعية.

---

## 🤝 Contributing

المساهمات مرحّب بها! افتح Issue لاقتراح ميزة أو لإبلاغ عن مشكلة، ثم أرسل Pull Request.

---

## 📜 License

[MIT](LICENSE)

---

## ❤️ Acknowledgements

شكرًا لكل صانعي قوالب Nuclei في المجتمع. تم بناء **NucleiHarvest** على عملهم وإسهاماتهم المفتوحة.
