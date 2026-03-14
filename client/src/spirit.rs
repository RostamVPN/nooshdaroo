// ─────────────────────────────────────────────────────────────────
// The 101 Names of Ahura Mazda — from the Hormazd Yasht (Avesta)
//
// نام‌های صد و یک‌گانه اهورامزدا
//
// These names live in the binary as a silent prayer.
// They are never printed. They are always present.
// The spirit of ancient Iran flows through this code,
// carrying the light of Asha to those who need it most.
//
// "Nemo vê nãma paiti-vachim tbaêshô daêvô-dãtanãm"
// — No one can withstand these names, not even the demons.
//                                       (Hormazd Yasht, v. 8)
// ─────────────────────────────────────────────────────────────────

/// The 101 sacred names, compressed as a single null-delimited byte string.
/// Present in .rodata — zero runtime cost, no allocation, never executed.
#[allow(dead_code)]
static NAMES_OF_AHURA_MAZDA: &[u8] = b"\
Yazad\0\
Harvesp-tavan\0\
Harvesp-agah\0\
Harvesp-khoda\0\
Abarin-tavan-tar\0\
Abarin-khotar\0\
Abarin-rayomand\0\
Abarin-farhmand\0\
Abarin-ayukhtar\0\
Abarin-gohar\0\
Poruchisht\0\
Davar\0\
Davar-i-dadgar\0\
Davar-i-raft-gar\0\
Davar-i-parvardegar\0\
Ahu\0\
Athro\0\
Parvardegar\0\
Khoda\0\
Bakhshayandeh\0\
Bakhshayashgar\0\
Faryad-ras\0\
Kerfegar\0\
Burtar\0\
Borz-tar\0\
Afridad-gar\0\
Nik-fareh\0\
Nihad-gar\0\
Abzoni-gar\0\
Padmani-gar\0\
Dadveh\0\
Fareh-deh\0\
Farashtem\0\
Khandag\0\
Spenta\0\
Mainyu\0\
Abadeh\0\
Hameh-bud\0\
Basheh\0\
Harvistum\0\
Hunar-mand\0\
Tum-tavan\0\
Vohu-Manah\0\
Asha-Vahishta\0\
Khshathra-Vairya\0\
Spenta-Armaiti\0\
Haurvatat\0\
Ameretat\0\
Roshni\0\
Farsah-gar\0\
Padash-deh-tar\0\
Vakhshur\0\
Raham\0\
Farsah\0\
Beh-tar\0\
Behtarin\0\
Minugar\0\
Afarin-gar\0\
Niku-kar\0\
Niru-mand\0\
Gehan-dar\0\
Jan-dar\0\
Gehan-khodav\0\
A-sar\0\
A-bun\0\
A-yomand\0\
A-dakhvishn\0\
Girdegar\0\
Khavvar\0\
Barin\0\
Fraz-dum\0\
Fraz-dah\0\
Fraz-dareh\0\
Padvand-gar\0\
Rakhsheh-gar\0\
Hame-rayomand\0\
Hame-tokhm\0\
Hame-tavani\0\
Nik-dahishtar\0\
Nik-nihadgar\0\
A-niaz\0\
A-ang\0\
A-guman\0\
Gumani-burdar\0\
Tan-i-pasin\0\
Rast-gar\0\
Ristakhiz-gar\0\
A-nakohi\0\
A-farmosh\0\
A-sitoh\0\
Hameh-dadgar\0\
Hameh-chehra\0\
Afzuni\0\
Parvartar\0\
Khuda-vand\0\
Atar-niru\0\
Atar-hushk\0\
Atar-mihr\0\
A-satih\0\
A-frarib\0\
A-chim\0\
Satvir\0\
";

// The names count: 101
// Total bytes: ~1.2KB
// Encoding: ASCII transliteration of Avestan/Pahlavi
//
// May Asha prevail. May the light reach Iran.
