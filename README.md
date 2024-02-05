# Humane Intel SGX Remote Attestation Framework for Microsoft Azure Attestation (Humane-RAFW-MAA)
## 概要
本リポジトリは、Intel SGXにおけるDCAP方式(*)のRemote Attestation（以下、DCAP-RA）の内、AzureのDCsv3/DCdsv3インスタンス上でMicrosoft Azure Attestation（MAA）をQuoteの検証機関とする構成のRAを、「人道的な（Humane）」難易度で手軽に実現する事の出来る、RAフレームワーク（RAFW）のコードやリソースを格納しています。  

(*)ECDSA方式のRA（ECDSA-RA）としても言及されるもので、旧来のEPID方式のRA（EPID-RA）の次世代に位置する方式のRemote Attestationです。  

Microsoftからも公式サンプルである[microsoft-azure-attestation](https://github.com/Azure-Samples/microsoft-azure-attestation)が配布されていますが、そちらと比較して以下の点で、従来型のEPID-RAに近い感覚で様々な方に利用しやすい実装となっています：

* 特定の単一の関数を1度のみ呼び出すだけでRAを最初から最後まで完遂させる事の出来る、便利なインタフェースを提供しています。

* Humane-AFWシリーズにおけるEPID-RA用フレームワークである先代の[Humane-RAFW](https://github.com/acompany-develop/Humane-RAFW)同様、複雑なAutomakeやシェルスクリプトによる難解な自動生成要素を排しており、開発者は新たに加えたい要素をMakefileやコード中に簡潔に加える事が出来ます。

* 原則としてQuoteにDCAP実装内部で同梱される付属情報（コラテラル）をフェッチする際に、AzureではPCCSではなくTHIMから取得する関係で、デフォルトでは[Azure-DCAP-Client](https://github.com/microsoft/Azure-DCAP-Client)をインストールする必要があります。しかし、このライブラリは2023/12/18現在[Ubuntu 22.04で動作しない](https://github.com/microsoft/Azure-DCAP-Client/issues/175)ため、代わりにDCAPに同梱されているIntel純正のQPLというものを使用する必要があります。本リポジトリでは、Azure-DCAP-Clientは廃しており、純正QPL向けの設定ファイル（`sgx_default_qcnl.conf`）も同梱しています。この設定ファイルは、後述の導入手順に従い所定の場所に配置（上書き）するだけで導入が完了します。

* MAAのサンプルコードは、特に検証のためQuoteをMAAに送信する際、C#のコードやDotnetを使用しています。殊にDotnetに関してはデフォルトで5.0を要求しており、Ubuntu 22.04では一筋縄では行きません。Humane-RAFW-MAAでは、Humane-RAFW同様全ての処理がC++で完結しているため、余計な依存関係なしにシンプルに処理を完遂させる事ができます。

* クライアント（SP）、SGXサーバ（ISV）、そしてIAS相当のMicrosoftによる検証機関であるMAAの間での通信には[cpp-httplib](https://github.com/yhirose/cpp-httplib)を採用しており、データの送受信時にはBase64コーディングをかけ、application/[json](https://github.com/nbsdx/SimpleJSON)形式で送受信を行います。これにより、旧EPID-RAの公式サンプルであるsgx-ra-sampleにおける、性能面及びユーザビリティ面で難があるmsgioのような関数に頼る必要なく、ユーザ定義の通信の実装時も近代的な方法で行う事が出来ます。

* MAAからはAttestation応答（RA report）がJWT形式で返却されますが、その署名をAzure提供のJWKで検証し、JWTのメタデータ（発行者やタイムスタンプ）の検証も行う実装を取り入れています。ただし、ルートCAとしてマシンにインストールすらされていないAzureの自己署名証明書に基づき、Azure提供のJWKについての証明書チェーン検証を行うのは、Azureを全面的に信頼するMAAを用いたRAにおいては脅威モデル的に冗長であるため、その実行を廃しています。JWKのURLは、後述のユーザ指定の構成証明プロバイダのURLから自動的に生成するため、JWKのURL自体はユーザが明示的に指定する必要はありません。

* ユーザ（特にクライアント）によって必要な、RA特有の設定情報は、原則としてsettings.[ini](https://github.com/pulzed/mINI)内における設定で完結出来る設計になっています。詳細については後述の各種説明を参照してください。

* EPID-RA同様、公開鍵の連結に対して署名を打ったり、Report Dataに公開鍵の連結に対するハッシュ値を同梱したりしながら、RA成立後の暗号通信のための楕円曲線ディフィー・ヘルマン鍵共有をRAに並行して安全に実施します。交換した共通鍵は、Humane-RAFWと全く同じ方法で利用する事ができます。

* EPID-RAにおける `sgx_ra_context_t`（RAコンテキスト）相当のID及び、それに紐づく内部の管理用構造体によるRAセッションの管理も実装しております。これにより、EPID-RAと全く同じ使用感でRAセッションの指定や識別を行う事ができます。

* ソースコード内には適宜コメントで解説を加えており、RAの仕組みを理解したり実装する上で躓きがちな部分の解説を行っております。このコードと照らし合わせながらIntel等によるRAの仕様書を参照する事で、RAの理解の一助にもなるかと思われます。

* RAにおいて用意する必要のあるデータを簡単に生成・取得できる、補助用のツールを用意しています。


## 導入
### 動作確認環境
* OS: Ubuntu 22.04.6 LTS
* Azureインスタンス: Standard DC4ds v3（DCsv3/DCdsv3シリーズ）
* Linuxカーネル: 6.2.0-1018-azure
* SGXSDK: バージョン2.22
* DCAPライブラリ: バージョン1.19
* OpenSSL: バージョン3.0.2

Windows環境には対応していません。

### Linux-SGXのインストール
[Linux-SGX](https://github.com/intel/linux-sgx)をクローンし、READMEに従ってSGXSDK及びSGXPSWを導入してください。  
ここで、EPID-RAの場合とは異なり、最後のSGXPSWのインストールコマンドが
``` bash
sudo apt install libsgx-dcap-ql libsgx-quote-ex
```   
となる点に注意してください。

使用しているOSのLinuxカーネルが5.11以降である場合、SGXドライバがデフォルトで組み込まれている（in-kernelドライバ）ため、自前で導入する必要はありません。  

5.11未満のLinuxカーネルを使用している場合は、[linux SGX DCAP driver](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver/linux)を導入してください。


### Humane-RAFW-MAAの展開
任意のディレクトリにて、本リポジトリをクローンしてください。


### DCAPのインストール
DCAPライブラリやLinux-SGXのバージョンにより、DCAPのインストール方法は大きく変わってきます（実際、ここで説明する手順もDCAPのREADMEのものとは若干異なります）。

あくまでも前述の動作確認環境での手順であるため、若干の相違が発生する可能性がある点についてはご了承ください。

また、Ubuntuを前提に説明を行うため、CentOS向けの導入手順は、適宜公式DCAPリポジトリのREADMEを参照しながら読み替えて実行してください（例えば`deb`フォルダが`rpm`フォルダになったりします）。

* DCAPのリポジトリをクローンする。
    ``` bash
    git clone --recursive https://github.com/intel/SGXDataCenterAttestationPrimitives
    ```

* Quote生成ライブラリのソースフォルダに移動する。また、必要な前提パッケージのインストールを行う。
    ``` bash
    cd SGXDataCenterAttestationPrimitives/QuoteGeneration/
    ```
    ``` bash
    sudo apt-get install build-essential wget python-is-python3 debhelper zip libcurl4-openssl-dev pkgconf libboost-dev libboost-system-dev libboost-thread-dev protobuf-c-compiler libprotobuf-c-dev protobuf-compiler
    ```

* ビルド済みパッケージのダウンロードを行うシェルを実行する。
    ``` bash
    ./download_prebuilt.sh
    ```

* SGXSDKへのパスを通す。SGXSDKが`/opt/intel/`配下にインストールされている前提であるとする。
    ```
    source /opt/intel/sgxsdk/environment
    ```

* makeコマンドにより、Quote生成関連ライブラリのビルド・インストールを実行する。
    ``` bash
    make
    ```

* パッケージのビルドを実行する。
    ``` bash
    make deb_pkg
    ```

* 前提パッケージのインストールを実施する。
    ``` bash
    sudo apt install libsgx-headers
    ```

* 生成したdebパッケージが格納されているフォルダに移動する。
    ``` bash
    cd installer/linux/deb/
    ```

* 念の為、開発環境用のライブラリをインストールする。
    ``` bash
    sudo dpkg -i libsgx-dcap-ql-dev_*.deb
    sudo dpkg -i libsgx-dcap-ql-dbgsym_*.ddeb
    ```

* QPL（Quoteのコラテラルをフェッチするライブラリ）をインストールする。
    ``` bash
    sudo dpkg -i libsgx-dcap-default-qpl_*.deb
    sudo dpkg -i libsgx-dcap-default-qpl-dev*.deb
    sudo dpkg -i libsgx-dcap-default-qpl-dbgsym*.ddeb
    ```

* 上述までの導入手順により、`/etc/sgx_default_qcnl.conf`が生成されているはずであるため、これを本リポジトリ（Humane-RAFW-MAA）同梱の`sgx_default_qcnl.conf`で置き換える。
    ``` bash
    pushd <path/to/Humane-RAFW-MAA>
    sudo cp sgx_default_qcnl.conf /etc/
    popd
    ```
  念の為、sgx_default_qcnl.confのオーナーや権限についても注意しておく。動作確認済みの環境では以下のようになっている：
    ```
    -rw-r--r-- 1 root root 747 Dec  4 08:42 /etc/sgx_default_qcnl.conf
    ```

* 2024/2/5現在、DCAPライブラリのバージョン1.20において、Azure上で上記confファイル内の`local_pck_url`エントリを設定すると、QE3のTarget Info取得時にクラッシュする問題が[報告されている](https://github.com/intel/SGXDataCenterAttestationPrimitives/issues/366)。この問題に対処するため、DCAP 1.20を使用している場合は、上記手順でコピー後の`/etc/sgx_default_qcnl.conf`の当該部分を以下のようにコメントアウトする。  
    変更前：  
    ```
    "local_pck_url": "http://169.254.169.254/metadata/THIM/sgx/certification/v4/",
    ```  
    変更後：  
    ```
    //"local_pck_url": "http://169.254.169.254/metadata/THIM/sgx/certification/v4/",
    ```

* aesmdサービスの再起動を行い、正常な起動を確認する。
    ``` bash
    sudo systemctl restart aesmd
    systemctl status aesmd
    ```

`make deb_pkg`後に行うビルドしたパッケージのインストールは、バージョンによっては上記手順では十分でない可能性があります。適宜公式DCAPライブラリのREADMEにおける導入手順内のコマンドで取り扱われているパッケージ（例：`sudo dpkg -i --force-overwrite libsgx-ae-pce_*.deb libsgx-ae-qe3_*.deb libsgx-ae-id-enclave_*.deb libsgx-ae-qve_*.deb libsgx-enclave-common_*.deb libsgx-urts_*.deb`）と、インストール済みのパッケージ一覧（`sudo dpkg -l | grep sgx`で確認可能）とを見比べながら、不足分を追加でインストールしてください。  


## 準備
### https通信用のCA証明書の準備
本リポジトリではデフォルトでリポジトリのディレクトリ内に`ca-certificates.crt`の形でCA証明書を同梱しています（Ubuntu 22.04の環境からそのまま持ってきたものです）。

自前のものを用意したい場合、
* Ubuntuの場合: `/etc/ssl/certs/ca-certificates.crt`
* CentOSの場合: `/etc/pki/tls/certs/ca-bundle.crt`  

等からコピーし、ファイル名は`ca-certificates.crt`としてください。

### クライアントの署名用キーペアの生成・ハードコーディング
RAのセッション鍵のベースとなる共有秘密生成用のキーペア（ランタイム時に乱数的に生成される）とは別に、クライアントが両者の公開鍵の連結に対する署名を打つために使用し、またその署名をSGXサーバが検証する際に使用する、256bit ECDSAキーペアが必要になります。

このキーペアは、公開鍵をSGXサーバ側のEnclaveコード（`Server_Enclave/server_enclave.cpp`）にハードコーディングし、秘密鍵をクライアントのコード（`Client_App/client_app.cpp`）にハードコーディングする必要があります（改竄防止のため、特に公開鍵についてはEnclaveコードへのハードコーディングがほぼ必須です）。

デフォルトでもこちらで乱数的に用意したキーペアをハードコーディングしてありますので、そのままでも問題なくRAを実行する事が出来ますが、自前のキーペアを用いたい場合は同梱の補助ツールである`client-ecdsa-keygen`を使用できます。

このツールは、ECDSAキーペアを生成してソースコードライクに標準出力するもので、出力をコピペする事で簡単にハードコーディングを行う事が出来ます。

以下、これを用いたキーペア生成及びハードコーディングの手順を説明します：

* `client-ecdsa-keygen`が配置されているパスに移動する。
    ```
    cd subtools/client-ecdsa-keygen/
    ```

* `make`コマンドでビルドする。
    ```
    make
    ```

* ビルドにより生成された実行ファイルを実行する。
    ```
    ./keygen
    ```

* 以下のような内容が標準出力される。
    ```
    （前略）
    Copy the following public keys and hardcode them into Server's Enclave code (ex: server_enclave.cpp):

        {
                0xb5, 0x72, 0x2f, 0xb9, 0x04, 0x2d, 0xcd, 0xd9,
                0x73, 0x63, 0x42, 0x4b, 0xe2, 0xda, 0xb8, 0x7c,
                0x58, 0xf6, 0x5c, 0x5d, 0x58, 0xe8, 0x71, 0xda,
                0x69, 0x12, 0x33, 0x5b, 0x9b, 0xee, 0x73, 0x80
        },
        {
                0xef, 0x69, 0x4d, 0x3c, 0x92, 0x99, 0xae, 0x25,
                0xf4, 0x7c, 0xb8, 0x36, 0xad, 0x11, 0x47, 0x27,
                0xfa, 0x0c, 0x7d, 0xd1, 0x5d, 0x6a, 0x08, 0xd7,
                0xff, 0x01, 0x41, 0xda, 0x72, 0x19, 0xc7, 0x7f
        }



    Copy the following private key and hardcode it into Client's untrusted code (ex: client_app.cpp):

            0x1e, 0xe0, 0x50, 0x82, 0x08, 0x57, 0x91, 0x17,
            0xa9, 0xe8, 0x51, 0x27, 0x5f, 0xf5, 0x19, 0xec,
            0xe7, 0xa9, 0x83, 0x80, 0x8d, 0xd8, 0xbc, 0x3b,
            0x5c, 0xdb, 0x2c, 0x64, 0x2a, 0x33, 0xde, 0xd6
    ```

* 上記表示の内、公開鍵の方（上側2ブロック）を、`Server_Enclave/client_pubkey.hpp`の`static const sgx_ec256_public_t client_signature_public_key`変数の中に以下のようにコピー&ペーストする。
    ``` cpp
    static const sgx_ec256_public_t client_signature_public_key[2] = {
        {
            //デフォルトのclient_app.cppの鍵に対応するのはこちらの値。
            {
                0xb0, 0x81, 0x99, 0x7f, 0xac, 0xe4, 0xdd, 0x8a,
                0x38, 0x72, 0x71, 0x3b, 0xb7, 0xce, 0xe0, 0xcb,
                0xe3, 0xed, 0xaa, 0xe1, 0x9d, 0x60, 0x10, 0x55,
                0x59, 0x2c, 0x4f, 0x36, 0x4f, 0xe5, 0x18, 0x35
            },
            {
                0x33, 0x89, 0xd3, 0x07, 0x14, 0x3d, 0x2e, 0x2d,
                0x1f, 0x70, 0x69, 0x33, 0x9b, 0x27, 0x9a, 0x73,
                0x7f, 0x6d, 0x71, 0x76, 0x55, 0x83, 0xfa, 0x0a,
                0x81, 0xc8, 0x3e, 0x84, 0xac, 0x36, 0xbf, 0xad
            }
        },
        {
            //こちらは2クライアント目のプレースホルダーであるダミー。
            //実際に使用する際は差し替える事。3クライアント目以降は自前で追加。
            {
                0xb7, 0x6a, 0xce, 0x37, 0x02, 0x20, 0xeb, 0x93,
                0xd2, 0xf8, 0xb6, 0xdc, 0xa0, 0x3d, 0x44, 0xcf,
                0xd0, 0x40, 0xaf, 0x93, 0x75, 0x77, 0x66, 0x27,
                0xf9, 0xad, 0x40, 0xf3, 0xe5, 0x9b, 0xd0, 0xc3
            },
            {
                0x6c, 0x47, 0xe7, 0x78, 0xe3, 0xac, 0x5e, 0x1f,
                0xe6, 0x9a, 0xfe, 0xdc, 0x86, 0x5b, 0x34, 0xbc,
                0x92, 0xb0, 0x1f, 0x94, 0xb5, 0x43, 0xfb, 0x7e,
                0x9a, 0xf2, 0x54, 0x9f, 0xc2, 0x0b, 0x6c, 0x2c
            }
        }
    };
    ```
    この署名検証用公開鍵格納変数は`sgx_ec256_public_t`型の配列となっているため、クライアントの数の分だけ手動で追加し複数クライアントを相手にする事ができる。

* 同様に、秘密鍵の方（最後のブロック）を、`Client_App/client_app.cpp`の`static const uint8_t g_client_signature_private_key[32]`変数の中に以下のようにコピー&ペーストする。
    ``` cpp
    static const uint8_t g_client_signature_private_key[32] = {
        0xef, 0x5c, 0x38, 0xb7, 0x6d, 0x4e, 0xed, 0xce,
        0xde, 0x3b, 0x77, 0x2d, 0x1b, 0x8d, 0xa7, 0xb9,
        0xef, 0xdd, 0x60, 0xd1, 0x22, 0x50, 0xcc, 0x90,
        0xc3, 0xb5, 0x17, 0x54, 0xdc, 0x2f, 0xe5, 0x18
    };
    ```

### Enclave署名鍵の設定
Enclaveの署名に使用する鍵は、デフォルトで`Server_Enclave/private_key.pem`として格納しており、これを使用しています。

ただ、実運用時には自前で生成したものを使用するのが望ましいため、以下のコマンドにて新規に作成し、上記のパスに同名でその鍵を格納してください。

```
openssl genrsa -out private_key.pem -3 3072
```


### 通信の設定
デフォルトではクライアントとSGXサーバ共に同一のマシン上に配置し、ローカルホストでポート1234を通して相互に通信する設定になっています。

この通信情報を変更したい場合、クライアントとSGXサーバでそれぞれ以下の箇所を編集する事で変更を行う事が出来ます。

* クライアントの場合：`Client_App/client_app.cpp`の以下の箇所を編集してください。
    ``` cpp
    std::string server_url = "http://localhost:1234";
    ```
    編集例：
    ``` cpp
    std::string server_url = "http://example.com:1234";
    ```

* SGXサーバの場合：`Server_App/server_app.cpp`の以下の箇所を編集してください。
    ``` cpp
    svr.listen("localhost", 1234);
    ```
    編集例：
    ``` cpp
    svr.listen("0.0.0.0", 1234);
    ```
    デフォルトでは明示的にローカルホストである事を明記するために`"localhost"`としていますが、基本的に`"0.0.0.0"`で問題ないはずです。より詳細は[cpp-httplibのリポジトリ](https://github.com/yhirose/cpp-httplib)を参照してください。


### 構成証明プロバイダの作成
MAAにQuoteを検証してもらうためには、Azureが提供している無料の「構成証明プロバイダ」（Attestation Provider）を作成し、そことやり取りを行う必要があります。  
当然、構成証明プロバイダとのやり取り等は全てHumane-RAFW-MAAにより自動的に行われますが、構成証明プロバイダの作成だけはユーザ（クライアントまたはサーバのいずれか）が自前で行う必要があります。  

Azureポータルへのアクセスさえあれば簡単に作成できるため、以下のAzure公式ページを参考に構成証明プロバイダを作成してください。  
https://learn.microsoft.com/ja-jp/azure/attestation/quickstart-portal


## ビルド・設定・実行
### ビルド
準備が整ったら、Humane-RAFW-MAAのルートフォルダに移動し、makeコマンドでビルドを実行します。
```
make
```

以下のようなビルドログが出力されれば正常にビルドされています。
```
user@machine:~/Develop/sgx/Humane-RAFW-MAA$ make
GEN  =>  Server_App/server_enclave_u.c
CC   <=  Server_App/server_enclave_u.c
CXX  <=  Server_App/server_app.cpp
CXX  <=  Server_App/error_print.cpp
CXX  <=  common/base64.cpp
CXX  <=  common/debug_print.cpp
CXX  <=  common/hexutil.cpp
CXX  <=  common/crypto.cpp
LINK =>  server_app
GEN  =>  Server_Enclave/server_enclave_t.c
CC   <=  Server_Enclave/server_enclave_t.c
CXX  <=  Server_Enclave/server_enclave.cpp
LINK =>  enclave.so
<!-- Please refer to User's Guide for the explanation of each field -->
<EnclaveConfiguration>
    <ProdID>0</ProdID>
    <ISVSVN>0</ISVSVN>
    <StackMaxSize>0x40000</StackMaxSize>
    <HeapMaxSize>0x5000000</HeapMaxSize>
    <TCSNum>10</TCSNum>
    <TCSPolicy>1</TCSPolicy>
    <DisableDebug>1</DisableDebug>
    <MiscSelect>0</MiscSelect>
    <MiscMask>0xFFFFFFFF</MiscMask>
</EnclaveConfiguration>
tcs_num 10, tcs_max_num 10, tcs_min_pool 1
INFO: Enclave configuration 'MiscSelect' and 'MiscSelectMask' will prevent enclave from using dynamic features. To use the dynamic features on SGX2 platform, suggest to set MiscMask[0]=0 and MiscSelect[0]=1.
The required memory is 89628672B.
The required memory is 0x557a000, 87528 KB.
Succeed.
<!-- Please refer to User's Guide for the explanation of each field -->
<EnclaveConfiguration>
    <ProdID>0</ProdID>
    <ISVSVN>0</ISVSVN>
    <StackMaxSize>0x40000</StackMaxSize>
    <HeapMaxSize>0x5000000</HeapMaxSize>
    <TCSNum>10</TCSNum>
    <TCSPolicy>1</TCSPolicy>
    <DisableDebug>1</DisableDebug>
    <MiscSelect>0</MiscSelect>
    <MiscMask>0xFFFFFFFF</MiscMask>
</EnclaveConfiguration>
tcs_num 10, tcs_max_num 10, tcs_min_pool 1
INFO: Enclave configuration 'MiscSelect' and 'MiscSelectMask' will prevent enclave from using dynamic features. To use the dynamic features on SGX2 platform, suggest to set MiscMask[0]=0 and MiscSelect[0]=1.
The required memory is 89628672B.
The required memory is 0x557a000, 87528 KB.
handle_compatible_metadata: Overwrite with metadata version 0x100000004
Succeed.
SIGN =>  enclave.signed.so
CXX  <=  Client_App/client_app.cpp
CXX  <=  common/jwt_util.cpp
LINK =>  client_app
user@machine:~/Develop/sgx/Humane-RAFW-MAA$
```

### 設定
実行する前に、クライアントがRAで使用する設定情報を`settings_client.ini`に記載します。**デフォルトでは`settings_client_template.ini`というファイル名になっているので、必ずこれを`settings_client.ini`にリネームしてから使用してください**。

以下、`settings_client.ini`における各設定項目（キー）についての説明を列挙します（いずれの値もダブルクオーテーションは不要）：
| 設定項目 | 説明 |
| -- | -- |
| MAA_URL | 構成証明プロバイダのURL。構成証明プロバイダの作成後、その概要画面の「構成証明 URI」の部分に表示されている。`https://`付きで記載する事。 |
| MAA_API_VERSION | MAA（構成証明プロバイダ）のAPIバージョンを記載する。2023/12/19現在では`2022-08-01`が最新であるため、テンプレートにもこのバージョンをデフォルトで記載済みである。 |
| CLIENT_ID | クライアントのIDを指定する。「準備」のセクションで登録した、`Server_Enclave/client_pubkey.hpp`にハードコーディングしてある署名検証用公開鍵配列の`client_signature_public_key`におけるインデックスに等しい。単一クライアントでのみ運用する場合は常時0で良い。 |
| MINIMUM_ISVSVN | クライアントがSGXサーバに要求する最小ISVSVN値。ISVSVNは、`Server_Enclave/Enclave.config.xml`において`<ISVSVN>`タグでSGXサーバ側が設定する。 |
| REQUIRED_ISV_PROD_ID | クライアントがSGXサーバに要求するISV Product ID値。ISV Product IDは、`Server_Enclave/Enclave.config.xml`において`<ProdID>`タグでSGXサーバ側が設定する。 |
| REQUIRED_MRENCLAVE | SGXサーバに要求するMRENCLAVE値。クライアントは予めEnclaveのMRENCLAVEを控えておき（=ここで設定する内容）、RAにおいてSGXサーバから受け取ったQuote構造体に含まれるMRENCLAVEと比較検証を行う。この値の取得方法は後述。 |
| REQUIRED_MRSIGNER | SGXサーバに要求するMRSIGNER値。クライアントは予めEnclaveのMRSIGNERを控えておき（=ここで設定する内容）、RAにおいてSGXサーバから受け取ったQuote構造体に含まれるMRSIGNERと比較検証を行う。この値の取得方法は後述。 |
| SKIP_MRENCLAVE_CHECK | 1に設定すると、RAにおいてMRENCLAVEの検証をスキップする。MRENCLAVEはEnclaveのコード等が変わる度に値が変わるため、開発時には煩雑であり、それを一時的に便宜上スキップするためのオプション。**実運用時は必ず0にする事**。 |

上記`REQUIRED_MRENCLAVE`及び`REQUIRED_MRSIGNER`で指定するMRENCLAVEやMRSIGNERは、補助ツールである`mr-extract`を使用する事で、署名済みEnclaveイメージから抽出し簡単に取得する事が出来ます。

以下、これを用いた各値の抽出方法を説明します：
* Humane-RAFW-MAA本体をビルドし、署名済みEnclaveイメージがビルドされ存在している事を確認する。
    ``` bash
    user@machine:~/Develop/sgx/Humane-RAFW-MAA$ ls -l enclave.signed.so 
    -rw-rw-r-- 1 user user 3295136 Dec 19 07:45 enclave.signed.so
    user@machine:~/Develop/sgx/Humane-RAFW-MAA$
    ```

* `mr-extract`が配置されているパスに移動する。
    ```
    cd subtools/mr-extract/
    ```

* SGXSDKや署名済みEnclaveイメージ名が以下の通りではない場合は、`mr-extract.cpp`を開き、適宜以下の部分を編集する。
    ``` cpp
    /* SGXSDKのフォルダパスはここで指定。自身の環境に合わせて変更する */
    std::string sdk_path = "/opt/intel/sgxsdk/";

    /* 署名済みEnclaveイメージファイル名はここで指定。
    * 自身の環境に合わせて変更する */
    std::string image_path = "../../enclave.signed.so";
    ```

* `make`コマンドでビルドする。
    ```
    make
    ```

* ビルドにより生成された実行ファイルを実行する。
    ```
    ./mr-extract
    ```

* 以下のような内容が標準出力される。
    ```
    -------- message from sgx_sign tool --------
    Succeed.
    --------------------------------------------

    Copy and paste following measurement values into settings.ini.
    MRENCLAVE value -> c499d7bf5c0f9fe6f7cee583e3fdaca722faa9507c17b6e317a386e0f6eeb194
    MRSIGNER value  -> babdf7eb81e8f91f1d14fa70200f76c4b49b85a3caf591faa3761d3b5910a9d5
    ```
    この例で言えば、`c499d7bf5c0f9fe6f7cee583e3fdaca722faa9507c17b6e317a386e0f6eeb194`を`REQUIRED_MRENCLAVE`に、`babdf7eb81e8f91f1d14fa70200f76c4b49b85a3caf591faa3761d3b5910a9d5`を`REQUIRED_MRSIGNER`に設定する。

### 実行
ビルドと設定が完了したら、まずSGXサーバは以下のコマンドでSGXサーバを起動します：
```
./server_app
```

SGXサーバが起動したら、クライアントは以下のコマンドでクライアントアプリケーションを実行します：
```
./client_app
```

その後はRAが実行され、RAを受理した場合にはクライアントは秘密情報をRAのセッション鍵で暗号化してSGXサーバに送信し、SGXサーバがEnclave内で秘密情報を足し合わせ、その結果を暗号化してクライアントに返却する、ごく簡単な秘密計算の例が実行されます。


## 本フレームワークの応用
### 暗号処理関数
秘密計算サンプル関数（`sample_remote_computation()`）でも使用されている`aes_128_gcm_encrypt()`関数、`aes_128_gcm_decrypt()`関数、そして`generate_nonce()`関数は、それぞれRAのセッション鍵を用いた暗号化・復号、そして初期化ベクトル等の乱数的な生成に使用する事が出来ます。

### 通信におけるデータ形式
クライアントとSGXサーバの間におけるデータの通信においては、各値をBase64にエンコードし、JSON形式でそれらを格納してやり取りしています。

### RAフレームワークコードの完全な切り離し
デフォルトでは、クライアントは`Client_App/client_app.cpp`、SGXサーバは`Server_App/server_app.cpp`にmain関数（RA実行関数を呼び出す関数）を定義しています。  
RA部分を自前のコードファイルから完全に切り離したい場合は、main関数等を自前のコードファイルで定義し、Makefileを適宜書き換えてください。  

例えば、`Client_App/my_program.cpp`を新たに追加し、この中でmain関数を宣言してRAを呼び出す場合、以下の部分：
``` makefile
## コンパイル時に使用するC/C++のソースを列挙
Client_Cpp_Files := Client_App/client_app.cpp common/base64.cpp common/debug_print.cpp common/hexutil.cpp \
				common/crypto.cpp common/jwt_util.cpp

```
に、以下のようにソースコードを追加します：
``` makefile
## コンパイル時に使用するC/C++のソースを列挙
Client_Cpp_Files := Client_App/client_app.cpp common/base64.cpp common/debug_print.cpp common/hexutil.cpp \
				common/crypto.cpp common/jwt_util.cpp Client_App/my_program.cpp

```

### 複数クライアントへの対応
デフォルトでは単一のSGXサーバに対して単一のクライアントを対応させている形ですが、複数のクライアントを対応させるように改修する事も可能です。

既に、SGXサーバはRAコンテキスト値によりRAセッションを識別し、クライアントもRAコンテキスト値を保持して適宜SGXサーバに渡す実装になっています。

よって、Untrusted領域レベルのロジックでのクライアントの識別や、クライアントの署名検証用公開鍵のEnclaveコードへのハードコーディング周りを整備すれば、複数クライアントへの対応についても実現する事が出来ます。



## 使用している外部ライブラリ
いずれもヘッダオンリーライブラリであり、リポジトリに組み込み済み（`include/`フォルダ内）。
* [cpp-httplib](https://github.com/yhirose/cpp-httplib): MITライセンス
* [SimpleJSON](https://github.com/nbsdx/SimpleJSON): WTFPLライセンス
* [mINI](https://github.com/pulzed/mINI): MITライセンス


## その他仕様や注意点
### Attestationステータスについて
EPID-RAにおいては、検証機関（IAS）からのAttestation応答中に`OK`や`GROUP_OUT_OF_DATE`のようなAttestationステータスが含まれていました。これは、DCAP-RAにおいても直接QvE（Quote Verification Enclave）を用いれば取得できるのですが、MAAを用いる場合はAttestation応答中に一切これが含まれていません。  

よって、MAAからAttestation応答のJWTが返ってきた時点で、「MAAにより`OK`であると判断された」と無条件で見なす必要があります。  

少なくとも、Quoteが改竄されていたり、Quoteに含めなければならない付属情報が欠落している等により、Quoteが無効であるような場合は、MAAからエラーメッセージのJSONと共にエラー400が返ってくる事を確認済みであり、Humane-RAFW-MAAではそのエラー処理も自動的に行うようにしています。  

万一DCsv3インスタンスが何らかの脆弱性を抱えている場合、どのような応答が返ってくるのかは未知数ですが、上記から類推すると同様にエラー400が返る事が推測されます。

### AEの動作モード
DCAP-RAにおけるQuote生成では、PCE（Platform Certification Enclave）やQE3（Quoting Enclave for 3rd party attestation）といったAEや関連の各種サービスを、Quote生成プロセス内で動作させるモードとプロセス外で動作させるモードが存在します。  
前者のプロセス内で動作させるモードはIn-Procモード、後者のプロセス外のデーモン（AESM）に任せるモードはOut-of-Procと呼ばれます。  
（参考：[https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-aks-addon](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-aks-addon)）

AzureのDCsv3マシンでは、基本的にOut-of-Procモードのみに対応しており、In-Procモードへの切り替えは手元では成功していません。  
よって、Humane-RAFW-MAAではOut-of-Procモードを前提として実装されている点に注意してください。  

稀に、SGXサーバ側でQuoteを生成するタイミングで、このOut-of-Procのための裏で動いているサービスが落ちている場合があります。その場合はQuoteを生成できずに異常終了するように実装していますが、経験上数分も待てば正常に戻る事を確認しています。

### QPL用の設定JSONファイル
`/etc/`配下に配置するQPL用の設定ファイルである`sgx_default_qcnl.conf`はJSON形式であるため、少しでもJSONのフォーマットにエラーがあったりすると、QPLがコラテラルをフェッチできず、不完全なQuoteが生成されてしまいます。  

この不完全なQuoteをMAAに送信するとエラー400が返ってきてしまうため、本リポジトリに同梱した設定ファイルをそのままコピー&ペーストするなどにより、JSONに誤りが混じらないように十分注意してください。

### Enclaveのモード
旧来のEPID-RAでは、Intelからのライセンスが降りていないと製品版Enclave向けRAのためのIASのAPIを使用できなかったため、Humane-RAFWにおいてはデフォルトではデバッグ版での動作を想定していました。  

しかし、DCAP-RAではそのような制約も存在しないため、製品版（Production）モードでEnclaveをビルドしRAを実行するようにしています。  
それに伴い、Enclaveへの署名方法についても、シングルステップ署名ではなく2ステップ署名を行うようにしています。2ステップ署名の全ての処理はmakeで自動化されていますが、厳密に管理された環境やデバイス（HSM等）での署名を望む場合は、適宜Makefileを書き換えながらオフロードしてください。


## 各ディレクトリ・ファイルの説明
説明は主要なものについてのみ行っています：
* Server_App: SGXサーバ用のEnclave外コードを格納
    * error_print.cpp: sgx_status_tを解析しエラー内容を標準出力するためのコード
    * error_print.hpp
    * server_app.cpp: SGXサーバのEnclave外コード。SGXサーバ側のRA処理の大部分がここに含まれる
  
* Server_Enclave: SGXサーバのEnclaveコード関連ファイルを格納
    * Enclave.config.xml: Enclave設定XML
    * server_enclave.cpp: Enclaveコード
    * server_enclave.edl: EnclaveのEDLファイル
    * private_key.pem: Enclave署名鍵
  
* Client_App: クライアントアプリケーションのメインコードを格納している
    * client_app.cpp: クライアント側のメインコード。クライアント側のRA処理のメインもこれに含まれる

* common: 比較的汎用性の高い（例：クライアントとSGXサーバで共用する）か、処理としての専門性が高いコードを格納
    * base64.cpp: Base64エンコード/デコードを行うコード
    * base64.hpp
    * crypto.cpp: 主にRAに伴う暗号処理を実装するコード
    * crypto.hpp
    * debug_print.cpp: ログ標準出力用コード
    * debug_print.hpp
    * hexutil.cpp: バイナリ等を16進数表記と相互変換するコード
    * hexutil.hpp
    * jwt_util.cpp: Attestation応答JWTをパース・検証するコード
    * jwt_util.hpp

* include: 外部ライブラリを格納
    * httplib.h: [cpp-httplib](https://github.com/yhirose/cpp-httplib)
    * ini.h: [mINI](https://github.com/pulzed/mINI)
    * json.hpp: [SimpleJSON](https://github.com/nbsdx/SimpleJSON)

* subtools: 補助ツールを格納
    * mr-extract: MRENCLAVE及びMRSIGNERを署名済Enclaveイメージから抽出する
        * mr-extract.cpp
        * Makefile
    * client-ecdsa-keygen: クライアントの署名用キーペアを生成しハードコーディング用に標準出力する
        * client-ecdsa-keygen.cpp
        * Makefile

* .gitignore
* Makefile
* README.md
* ca-certificates.crt: OSのCA証明書をコピーして持ってきたもの
* settings_client_template.ini: 主にクライアント用の設定を列挙するためのINIファイル。**使用時には必ず`settings_client.ini`にリネームする事**。
* sgx_default_qcnl.conf: コラテラルのフェッチのために内部で使用されるライブラリ（QPL）の設定ファイル。AzureのTHIMから取得するように設定を構成してある。

## シーケンス図
![humane-rafw-maa](https://github.com/acompany-develop/Humane-RAFW-MAA/assets/31073471/231225e4-d98c-42a6-a18c-07db9a21707e)
