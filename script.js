/**
 * ---------------------------------------------------------
 * RSA x 114514 惡臭加密器 - 終極修復版 (NSYSU IM)
 * 解決 ReferenceError 與 Unexpected end of input
 * ---------------------------------------------------------
 */

// 1. 全域變數定義 (絕對必須放在最上方)
const HOMO_BASES = [114514, 514, 114, 14, 11, 5, 4, 1];

/**
 * 114514 遞迴演算法 (已修正堆疊溢位)
 */
function getHomo(n) {
    if (n === 0) return "0";
    if (n < 0) return `-( ${getHomo(Math.abs(n))} )`;
    if (HOMO_BASES.includes(n)) return n.toString();

    // 處理 10 以下小數字，直接加法，避免 base=1 的無限遞迴
    if (n < 11) {
        return new Array(n).fill("1").join("+");
    }

    for (let base of HOMO_BASES) {
        if (n >= base && base > 1) { 
            let q = Math.floor(n / base);
            let r = n % base;
            let qStr = (q === 1) ? "" : `*(${getHomo(q)})`;
            let res = `${base}${qStr}`;
            if (r > 0) res += `+(${getHomo(r)})`;
            return res;
        }
    }
    return new Array(n).fill("1").join("+");
}

/**
 * PEM 格式自動補全
 */
function formatPEM(rawKey, type = "PUBLIC") {
    let cleanKey = rawKey.trim();
    if (!cleanKey) return "";
    if (!cleanKey.includes("-----BEGIN")) {
        return `-----BEGIN ${type} KEY-----\n${cleanKey}\n-----END ${type} KEY-----`;
    }
    return cleanKey;
}

/**
 * 加密邏輯
 */
function doEncrypt() {
    const rawKey = document.getElementById('keyInput').value;
    const text = document.getElementById('plainInput').value;
    
    if (!rawKey || !text) return alert("請輸入金鑰與明文！");

    const pubKey = formatPEM(rawKey, "PUBLIC");
    localStorage.setItem('rsa_key_cache', rawKey);

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(pubKey);
    const rsaRes = encryptor.encrypt(text);

    if (!rsaRes) return alert("RSA 加密失敗，請檢查公鑰格式。");

    // 產生密文算式
    const homoFormula = rsaRes.split('').map(char => {
        return `[${getHomo(char.charCodeAt(0))}]`;
    }).join('+');

    document.getElementById('cipherOutput').innerText = homoFormula;
}

/**
 * 解密邏輯 (強化空值檢查，解決 Unexpected end of input)
 */
function doDecrypt() {
    const rawKey = document.getElementById('keyInput').value;
    // 取得內容並去除前後空白
    const formula = document.getElementById('cipherOutput').innerText.trim();

    if (!rawKey || !formula || formula.includes("這裡將顯示") || formula.includes("等待")) {
        return alert("請輸入私鑰與有效的算式密文！");
    }

    const privKey = formatPEM(rawKey, "PRIVATE");
    localStorage.setItem('rsa_key_cache', rawKey);

    try {
        // 分解算式
        const segments = formula.split('+');
        let base64Result = "";

        for (let seg of segments) {
            let s = seg.trim();
            if (!s) continue; // 跳過空的加號間隙

            // 移除中括號
            let cleanSeg = s.replace(/[\[\]]/g, '').trim();
            
            // 重要：如果移除括號後是空的，代表這段算式無效，跳過以防 eval 出錯
            if (cleanSeg.length === 0) continue;

            try {
                // 使用 new Function 替代直接 eval，稍微安全且效能較好
                const val = new Function(`return ${cleanSeg}`)();
                if (typeof val === 'number') {
                    base64Result += String.fromCharCode(val);
                }
            } catch (evalErr) {
                console.error("算式解析失敗的片段:", cleanSeg);
                // 繼續嘗試下一段，不直接中斷
            }
        }

        if (!base64Result) throw new Error("算式還原後為空");

        const decryptor = new JSEncrypt();
        decryptor.setPrivateKey(privKey);
        const result = decryptor.decrypt(base64Result);

        if (result) {
            document.getElementById('plainInput').value = result;
        } else {
            alert("解密失敗！私鑰與公鑰不匹配。");
        }
    } catch (e) {
        console.error("解密過程出錯:", e);
        alert("解析錯誤: " + e.message);
    }
}

/**
 * 金鑰生成與初始化
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({default_key_size: 1024});
    alert("正在生成金鑰對...");
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    document.getElementById('keyInput').value = pub;
    console.log("--- 測試用私鑰 ---");
    console.log(priv);
    alert("公鑰已填入。私鑰已印在 Console (F12)，請務必複製存檔！");
}

window.onload = function() {
    const savedKey = localStorage.getItem('rsa_key_cache');
    if (savedKey) document.getElementById('keyInput').value = savedKey;

    const keyArea = document.getElementById('keyInput');
    keyArea.addEventListener('dragover', (e) => e.preventDefault());
    keyArea.addEventListener('drop', (e) => {
        e.preventDefault();
        const file = e.dataTransfer.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (ev) => {
                keyArea.value = ev.target.result;
                localStorage.setItem('rsa_key_cache', ev.target.result);
            };
            reader.readAsText(file);
        }
    });
};