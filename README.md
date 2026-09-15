# توثيق مشروع ClickJack (أداة فحص واختبار حماية الـ Clickjacking)

## 1. المشكلة (The Problem)
تعتبر ثغرة الاختطاف النقري (Clickjacking - UI Redress) من الهجمات الخطيرة في أمن تطبيقات الويب، حيث يتم خداع المستخدم عبر إخفاء صفحة خبيثة أو واجهة شفافة فوق صفحة حقيقية لموقع موثوق، مما يدفع المستخدم للضغط على أزرار أو روابط دون علمهم. الكثير من المواقع لا توفر الحماية الكافية عبر الترويسات الأمنية المناسبة مثل X-Frame-Options أو سياسة Content-Security-Policy (CSP).

## 2. فكرة المشروع (Project Idea)
مشروع ClickJack هو أداة أمنية عملية مكتوبة بلغة بايثون الخالصة (Pure Python) بدون الاعتماد على أي مكتبات خارجية (Third-party Libraries)، وتهدف إلى فحص استجابة المواقع الإلكترونية وتحليل الترويسات الأمنية المتعلقة بمنع الإطار (Framing)، بالإضافة إلى توليد ملف إثبات مفهوم تعليمي (Educational PoC) آمن للمساعدة في تقييم المخاطر واختبار الدفاعات.

## 3. الهدف من المشروع (Project Goals)
* فحص وتقييم ترويسات الحماية ضد الـ Clickjacking للمواقع المستهدفة بدقة.
* تطبيق مفاهيم البرمجة الآمنة وهندسة أدوات سطر الأوامر (CLI) باستخدام مكتبات بايثون القياسية فقط.
* توفير وسيلة آمنة للتحقق من وجود الثغرة وتوليد تقارير بصيغة JSON أو ملفات PoC للاختبار.

## 4. طريقة تشغيل الأداة (Usage & Commands)
تتميز الأداة بواجهة سطر أوامر تفاعلية (CLI) تدعم الأوامر الفرعية:
- عرض المساعدة: python clickjack.py --help
- فحص موقع: python clickjack.py scan --url https://example.com --report json
- توليد PoC: python clickjack.py poc --url https://example.com --output my_poc.html
- عرض تقرير: python clickjack.py report --input clickjack_report.json

## 5. النتائج والمخرجات (Results & Outputs)
* تقييم دقيق لحالة الموقع (PROTECTED, PARTIALLY PROTECTED, POTENTIALLY VULNERABLE).
* حساب نقاط أمنية (Score) من 100 وتحديد مستوى الخطر.
* إصدار تقارير JSON منظمة وملفات HTML تعليمية آمنة.