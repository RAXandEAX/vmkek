#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Ru,
}

impl Lang {
    pub fn parse(text: &str) -> Self {
        if text.eq_ignore_ascii_case("ru") {
            Self::Ru
        } else {
            Self::En
        }
    }
}

pub fn help(lang: Lang) -> &'static str {
    match lang {
        Lang::En => {
            "vmkek — protect PE32+ x86-64 images\n\n\
             Usage:\n  \
             vmkek protect <input> -o <output> [--virtualize SYM|rva:HEX[+SIZE]]... [--mutate SYM|rva:HEX[+SIZE]]... [--seed N] [--deterministic | --random-key] [--debug-seed] [--config FILE] [--virtualize-all] [--mutate-all] [--windows-native] [--lang en|ru]\n  \
             vmkek inspect <file> [--key HEX] [--config FILE] [--lang en|ru]\n  \
             vmkek report <file.report.json>\n  \
             vmkek run-native <file> --sha256 HEX [-- ARGS...] (Linux)\n  \
             vmkek run <file> [--key HEX] [--config FILE] [--lang en|ru]\n\n\
             With no arguments, this help is printed.\n\
             Default protect mode is --deterministic: ChaCha20-Poly1305 and the P-256 key come from HKDF-SHA256 of --seed.\n\
             --random-key draws those keys from the OS RNG. --debug-seed writes the seed into the report and is off by default.\n\
             PE lab startup: add --windows-native --authenticated-lab --manufacturer-signing-key FILE --manufacturer-public-key FILE --application-id HEX.\n\
             inspect and run of a protected image require the public key via --key or public_key in --config.\n\
             run-native takes a trusted deployment digest and launches with an empty environment.\n\
             Default language is English. VMKEK_LANG=ru selects Russian.\n"
        }
        Lang::Ru => {
            "vmkek — защита образов PE32+ x86-64\n\n\
             Использование:\n  \
             vmkek protect <вход> -o <выход> [--virtualize СИМВОЛ|rva:HEX[+SIZE]]... [--mutate СИМВОЛ|rva:HEX[+SIZE]]... [--seed N] [--deterministic | --random-key] [--debug-seed] [--config ФАЙЛ] [--virtualize-all] [--mutate-all] [--windows-native] [--lang en|ru]\n  \
             vmkek inspect <файл> [--key HEX] [--config ФАЙЛ] [--lang en|ru]\n  \
             vmkek report <файл.report.json>\n  \
             vmkek run-native <файл> --sha256 HEX [-- АРГУМЕНТЫ...] (Linux)\n  \
             vmkek run <файл> [--key HEX] [--config ФАЙЛ] [--lang en|ru]\n\n\
             Без аргументов печатается эта справка.\n\
             Режим по умолчанию — --deterministic: ChaCha20-Poly1305 и ключ P-256 выводятся HKDF-SHA256 из --seed.\n\
             --random-key берёт эти ключи из OS RNG. --debug-seed пишет seed в отчёт и по умолчанию выключен.\n\
             Запуск PE в лаборатории: добавьте --windows-native --authenticated-lab --manufacturer-signing-key FILE --manufacturer-public-key FILE --application-id HEX.\n\
             inspect и run защищённого образа требуют публичный ключ через --key или public_key в --config.\n\
             run-native принимает хэш из доверенной конфигурации развёртывания и запускает ELF с пустым окружением.\n\
             Язык по умолчанию — английский. VMKEK_LANG=ru включает русский.\n"
        }
    }
}

pub fn t(lang: Lang, key: &str) -> &'static str {
    match (lang, key) {
        (Lang::Ru, "protected") => "защищённый образ записан",
        (Lang::Ru, "inspected") => "подпись P-256 верна",
        (Lang::Ru, "bad-sig") => "подпись P-256 не сошлась",
        (Lang::Ru, "running") => "запуск",
        (Lang::En, "protected") => "protected image written",
        (Lang::En, "inspected") => "P-256 signature verified",
        (Lang::En, "bad-sig") => "P-256 signature did not verify",
        _ => "running",
    }
}
