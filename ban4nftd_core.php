<?php
// ------------------------------------------------------------
// 
// BAN for nftables
// 
// T.Kabu/MyDNS.JP           http://www.MyDNS.JP/
// Future Versatile Group    http://www.fvg-on.net/
// 
// ------------------------------------------------------------
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
require(__DIR__."/ban4nftd_ban.php");
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
require(__DIR__."/ban4nftd_unban.php");
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
require(__DIR__."/ban4nftd_exec.php");
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function issbanlistget($TARGET_INFO)
{
    // 情報共有サーバーのBANデータベースからBAN情報を取ってくるための変数を設定
    $ISS_INFO = array(
        "iss_get_time" => $TARGET_INFO['iss_get_time'],
        "iss_get_limit" => $TARGET_INFO['iss_get_limit'],
        "iss_get_myreport" => $TARGET_INFO['iss_get_myreport']
        );
    
    // JSON形式に変換
    $ISS_JSON = json_encode($ISS_INFO);
     
    // ストリームコンテキストのオプションを作成
    $ISS_OPTION = array(
        // HTTPコンテキストオプションをセット
        'http' => array(
        'method'=> 'POST',
        'header'=> 'Content-type: application/json; charset=UTF-8', //JSON形式を指定
        'content' => $ISS_JSON
        )
    );
    
    // ストリームコンテキストの作成
    $ISS_CONTEXT = stream_context_create($ISS_OPTION);
    
    // POST送信
    $ISS_RESULT = @file_get_contents('https://'.$TARGET_INFO['iss_username'].':'.$TARGET_INFO['iss_password'].'@'.$TARGET_INFO['iss_server'].'/banget.html', false, $ISS_CONTEXT);
    
    // POST出来なかったら
    if ($ISS_RESULT === false)
    {
        $TARGET_INFO['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: ERROR [iss-list] "."Cannot get Ban List!? "."\n";
        // ログに出力する
        log_write($TARGET_INFO);
    }
    // BAN情報一覧の取得ができたら
    else
    {
        // BAN情報が必要最低限長(75文字)もなかったら
        if (strlen($ISS_RESULT) < 72)
        {
            $TARGET_INFO['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: INFO [iss-list] "."None new Ban List"."\n";
            // ログに出力する
            log_write($TARGET_INFO);
        }
        // JSON エンコードされたBAN情報一覧をPHPの変数に変換、出来なかったら
        else if (($ISS_BAN_LIST = json_decode($ISS_RESULT, TRUE)) == NULL)
        {
            $TARGET_INFO['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: ERROR [iss-list] "."Cannot decode Ban List!? ".$ISS_RESULT."\n";
            // ログに出力する
            log_write($TARGET_INFO);
        }
        // BAN情報一覧をPHPの変数に変換出来たら
        else
        {
            // 変数化したBAN情報一覧を一つずつBANする
            foreach ($ISS_BAN_LIST as $ISS_BAN_INFO)
            {
                // BANする(UNIXタイム)
                $TARGET_INFO['target_address'] = $ISS_BAN_INFO['address'];
                $TARGET_INFO['target_service'] = $ISS_BAN_INFO['service'];
                $TARGET_INFO['target_protcol'] = $ISS_BAN_INFO['protcol'];
                $TARGET_INFO['target_port'] = $ISS_BAN_INFO['port'];
                $TARGET_INFO['target_rule'] = $ISS_BAN_INFO['rule'];
////                $TARGET_INFO['logtime'] = local_time();
                $TARGET_INFO['logtime'] = time();
                $TARGET_INFO = ban4nft_ban($TARGET_INFO);
                // ログに出力する
                log_write($TARGET_INFO);
            }
        }
    }
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4nft_mail_send()
{
    // メール送信のパラメータを設定(それぞれのプロセスのTARGET_CONFがなかったり、宛先がなかったらFALSEで戻る。それ以外は空でも送信処理をする)
    $MAIL_ARG = func_get_args();
    // それぞれのプロセスのTARGET_CONFが設定されていなかったり、配列でなかったら
    if (!isset($MAIL_ARG[0]) || !is_array($MAIL_ARG[0]))
    {
        // FALSEで戻る
        return FALSE;
    }
    // パラメータがあるなら
    else
    {
        // TARGET_CONFを設定
        $TARGET_CONF = $MAIL_ARG[0];
    }
    
    // 宛先に相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[1]))
    {
        // FALSEで戻る
        return FALSE;
    }
    // パラメータがあるなら
    else
    {
        // 宛先を設定
        $MAIL_TO = $MAIL_ARG[1];
    }
    
    // タイトルに相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[2]))
    {
        // NULLを設定
        $MAIL_TITLE = NULL;
    }
    // パラメータがあるなら
    else
    {
        // タイトルを設定
        $MAIL_TITLE = $MAIL_ARG[2];
    }
    
    // 本文に相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[3]))
    {
        // NULLを設定
        $MAIL_STR = NULL;
    }
    // パラメータがあるなら
    else
    {
        // 本文を設定
        $MAIL_STR = $MAIL_ARG[3];
    }
    
    // ヘッダーオプションに相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[4]))
    {
        // NULLを設定
        $MAIL_HEADER = NULL;
    }
    // パラメータがあるなら
    else
    {
        // ヘッダーオプションを設定
        $MAIL_HEADER = $MAIL_ARG[4];
    }
    
    // メールオプションに相当するパラメータが設定されていないなら
    if (!isset($MAIL_ARG[5]))
    {
        // NULLを設定
        $MAIL_PARAM = NULL;
    }
    // パラメータがあるなら
    else
    {
        // メールオプションを設定
        $MAIL_PARAM = $MAIL_ARG[5];
    }
    
    // メール送信レートテーブルから、対象メッセージの現在時刻 - 対象時間より昔のデータを削除
    $SQL_STR = "DELETE FROM mailrate_tbl WHERE registdate < (".(time() - $TARGET_CONF['mailratetime']).");";
    try {
        $RESULT = $TARGET_CONF['mailrate_db']->exec($SQL_STR);
    }
    catch (PDOException $PDO_E) {
        // エラーの旨メッセージを設定
        $TARGET_CONF['log_msg'] .= date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: WARN PDOException:".$PDO_E->getMessage()." on ".__FILE__.":".__LINE__."\n";
    }
    // メール送信レートテーブルに対象メッセージを登録
    $SQL_STR = "INSERT INTO mailrate_tbl VALUES ('".$MAIL_TO."','".$MAIL_TITLE."',".time().");";
    try {
        $RESULT = $TARGET_CONF['mailrate_db']->exec($SQL_STR);
    }
    catch (PDOException $PDO_E) {
        // エラーの旨メッセージを設定
        $TARGET_CONF['log_msg'] .= date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: WARN PDOException:".$PDO_E->getMessage()." on ".__FILE__.":".__LINE__."\n";
        $RESULT = 0;
    }
    
    // もし新しく登録できたら
    if ($RESULT != 0)
    {
        // メール送信
        $RESULT = mb_send_mail(
                $MAIL_TO,
                $MAIL_TITLE,
                $MAIL_STR.$RESULT,
                $MAIL_HEADER,
                $MAIL_PARAM);
    }
    else
    {
        // メールは送信しない
    }
    // 戻る
    return $RESULT;
}
?>
<?php
// ----------------------------------------------------------------------
// Sub Routine
// ----------------------------------------------------------------------
function ban4nft_end($signo)
{
    global $BAN4NFTD_CONF;
    
    // フォークした子プロセスがあるなら
    if (isset($BAN4NFTD_CONF['proclist']) && is_array($BAN4NFTD_CONF['proclist']))
    {
        // フォークした子プロセスをkillする
        foreach ($BAN4NFTD_CONF['proclist'] as $PID)
        {
            // 子プロセスをkillする
            posix_kill($PID, SIGTERM);
            // 子プロセスの終了を待つ
            pcntl_waitpid($PID, $STATUS, WUNTRACED);
        }
    }
    unset($BAN4NFTD_CONF['proclist']);
    
    // シグナル別に処理
    switch ($signo)
    {
        // SIGINTなら
        case SIGINT:
        // SIGTERMなら
        case SIGTERM:
            // ソケットファイルがあれば
            if (is_executable($BAN4NFTD_CONF['socket_file']))
            {
                // UNIXソケットを閉じる
                socket_close($BAN4NFTD_CONF['socket']);
                // ソケットファイルを削除する
                unlink($BAN4NFTD_CONF['socket_file']);
            }
            
            // チェインからBAN4NFTチェインを削除
            system($BAN4NFTD_CONF['nft'].' delete chain ip filter '.$BAN4NFTD_CONF['nft_chain'].' > /dev/null');
            // チェインからBAN4NFTチェインを削除
            system($BAN4NFTD_CONF['nft'].' delete chain ip6 filter '.$BAN4NFTD_CONF['nft_chain'].' > /dev/null');
            
            // PIDファイルがあれば
            if (is_file($BAN4NFTD_CONF['pid_file']))
            {
                // PIDファイルを削除する
                unlink($BAN4NFTD_CONF['pid_file']);
            }
            
            $BAN4NFTD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: END"."\n";
            // ログに出力する
            log_write($BAN4NFTD_CONF);
            // ログファイルポインタが開かれているなら
            if (isset($BAN4NFTD_CONF['log_p']))
            {
                // ログファイルを閉じる
                fclose($BAN4NFTD_CONF['log_p']);
            }
            // 終わり
            exit;
            break;
        // SIGHUPなら
        case SIGHUP:
            // ソケットファイルがあれば
            if (is_executable($BAN4NFTD_CONF['socket_file']))
            {
                // UNIXソケットを閉じる
                socket_close($BAN4NFTD_CONF['socket']);
                // ソケットファイルを削除する
                unlink($BAN4NFTD_CONF['socket_file']);
            }
            
            // 再読み込み要求(=1)を設定
            $BAN4NFTD_CONF['reload'] = 1;
            $BAN4NFTD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: RELOAD"."\n";
            // ログに出力する
            log_write($BAN4NFTD_CONF);
            // ログファイルポインタが開かれているなら
            if (isset($BAN4NFTD_CONF['log_p']))
            {
                // ログファイルを閉じる
                fclose($BAN4NFTD_CONF['log_p']);
            }
            break;
    }
}
?>
<?php
// ----------------------------------------------------------------------
// Check Other process
// ----------------------------------------------------------------------
// PIDファイルがあるなら
if (is_file($BAN4NFTD_CONF['pid_file']))
{
    // エラーメッセージに、別のプロセスがある旨を設定
    $ERR_MSG = 'Found other process : '.$BAN4NFTD_CONF['pid_file'].'!?';
    // メッセージを表示
    print "\n".'ban4nftd ... '.$ERR_MSG."\n\n";
    // 終わり
    exit -1;
}
// ないなら
else
{
    // ログファイルの指定があるなら
    if (isset($BAN4NFTD_CONF['log_file']))
    {
        // ファイルをtouch(無ければ新規作成)
        touch($BAN4NFTD_CONF['log_file']);
        // ファイルのパーミッションを700に設定
        chmod($BAN4NFTD_CONF['log_file'], 0600);
    }
    // PIDファイルを新規に開く
    $PID_FILE = fopen($BAN4NFTD_CONF['pid_file'], "a");
    // PIDファイルにプロセスIDを出力(改行しない)
    fputs($PID_FILE, getmypid());
    // PIDファイルを閉じる
    fclose($PID_FILE);
}
?>
<?php
// ----------------------------------------------------------------------
// Check nft
// ----------------------------------------------------------------------
// nft
if (!is_executable($BAN4NFTD_CONF['nft']))
{
    fprintf(STDERR, "Cannot execute nft!?\n");
    exit -1;
}


// -----------------------------
// nftablesからBAN4NFTチェインを削除する
// -----------------------------
// IPv4でnftablesに設定されているチェインの設定を取得する
$PROC_P = popen($BAN4NFTD_CONF['nft'].' list chains ip', "r");
$TARGET_PATTERN = '/chain '.$BAN4NFTD_CONF['nft_chain'].' \{/';
// チェインにBAN4NFTチェインがあるなら
if (psearch($PROC_P, $TARGET_PATTERN) == TRUE)
{
    // チェインからBAN4NFTチェインを削除
    system($BAN4NFTD_CONF['nft'].' delete chain ip filter '.$BAN4NFTD_CONF['nft_chain'].' > /dev/null');
}
pclose($PROC_P);

// IPv6でnftablesに設定されているチェインの設定を取得する
$PROC_P = popen($BAN4NFTD_CONF['nft'].' list chains ip6', "r");
$TARGET_PATTERN = '/chain '.$BAN4NFTD_CONF['nft_chain'].' \{/';
// チェインにBAN4NFTチェインがあるなら
if (psearch($PROC_P, $TARGET_PATTERN) == TRUE)
{
    // チェインからBAN4NFTチェインを削除
    system($BAN4NFTD_CONF['nft'].' delete chain ip6 filter '.$BAN4NFTD_CONF['nft_chain'].' > /dev/null');
}
pclose($PROC_P);


// -----------------------------
// nftablesにBAN4NFTチェインを新設する
// -----------------------------
system($BAN4NFTD_CONF['nft'].' add chain ip filter '.$BAN4NFTD_CONF['nft_chain'].' { type filter hook input priority -1\;}');
system($BAN4NFTD_CONF['nft'].' add chain ip6 filter '.$BAN4NFTD_CONF['nft_chain'].' { type filter hook input priority -1\;}');

?>
<?php
// ----------------------------------------------------------------------
// Main (ここで監視設定(.conf)毎にプロセスを再度フォークする)
// ----------------------------------------------------------------------
do // SIGHUPに対応したループ構造にしている
{
    // 再読み込み要求を初期化
    $BAN4NFTD_CONF['reload'] = 0;
    
    // 情報共有フラグがON(=1)なら
    if (isset($BAN4NFTD_CONF['iss_flag']) && $BAN4NFTD_CONF['iss_flag'] == 1)
    {
        // 初回だけは、過去の自分の報告も取得＆反映させる
        $ORG_INFO['iss_get_myreport'] = $BAN4NFTD_CONF['iss_get_myreport'];
        $BAN4NFTD_CONF['iss_get_myreport'] = 1;
        
        // 情報共有サーバーのBANデータベースからBAN情報を取ってくる
        issbanlistget($BAN4NFTD_CONF);
        
        // 情報共有サーバーからBAN情報を取得した最終日時を設定
        $BAN4NFTD_CONF['iss_last_time'] = time();
        //自分のBAN報告の取得設定を元の設定に戻す
        $BAN4NFTD_CONF['iss_get_myreport'] = $ORG_INFO['iss_get_myreport'];
    }
    
    // サブ設定ディレクトリの設定があるなら
    if (isset($BAN4NFTD_CONF['conf_dir']) && is_dir($BAN4NFTD_CONF['conf_dir']))
    {
        // サブ設定ディレクトリを開く
        $CONF_DIR = opendir($BAN4NFTD_CONF['conf_dir']);
        // サブ設定ディレクトリからファイルの一覧を取得
        while (($CONF_FILE = readdir($CONF_DIR)) !== false)
        {
            $BAN4NFTD_CONF['conf_file'] = $BAN4NFTD_CONF['conf_dir'].'/'.$CONF_FILE;
            // サブ設定ファイルなら
            if (is_file($BAN4NFTD_CONF['conf_file']) && preg_match('/.conf$/', $BAN4NFTD_CONF['conf_file']))
            {
                // プロセスをフォーク
                $PID = pcntl_fork();
                
                // フォークできなかったら
                if ($PID == -1)
                {
                    // エラーメッセージに、プロセスをフォークできない旨を設定
                    $ERR_MSG = 'Cannot fork process'.'!?';
                    // メッセージを表示
                    print "\n".'ban4nftd ... '.$ERR_MSG."\n\n";
                    // 終わり
                    exit -1;
                }
                // フォークできたら
                else if ($PID != 0)
                {
                    // 親プロセスの場合
                    $BAN4NFTD_CONF['proclist'][] = $PID;
                }
                // 子プロセスなら
                else // if ($PID == 0)
                {
                    // 子プロセス用のサブルーチンファイルを読み込み
                    require(__DIR__.'/ban4nftd_sub.php');
                    // サブ設定ファイルを読み込んで変数展開する
                    $TARGET_CONF = array_merge($BAN4NFTD_CONF, parse_ini_file($BAN4NFTD_CONF['conf_file'], FALSE, INI_SCANNER_NORMAL));
                    // 実際の処理を開始
                    ban4nft_start($TARGET_CONF);
                    // ここで終わり(子プロセスなので)
                    exit;
                }
            }
        }
        closedir($CONF_DIR);
        
        // シグナルハンドラを設定します(親プロセスだけ)
        declare(ticks = 1);
        pcntl_signal(SIGINT,  "ban4nft_end");
        pcntl_signal(SIGTERM, "ban4nft_end");
        pcntl_signal(SIGHUP,  "ban4nft_end");
        
        // 親プロセスとしてUNIXソケットを開く
        $BAN4NFTD_CONF['socket'] = socket_create(AF_UNIX, SOCK_DGRAM, 0);
        // UNIXソケットが開けなかったら
        if ($BAN4NFTD_CONF['socket'] == FALSE )
        {
            // エラーメッセージに、UNIXソケットを開けない旨を設定
            $ERR_MSG = 'Cannot create socket'.'!?';
            // メッセージを表示
            print "\n".'ban4nftd ... '.$ERR_MSG."\n\n";
            // 終わり
            ban4nft_end(SIGTERM);
        }
        // UNIXソケットとファイルがBINDできなかったら
        if (socket_bind($BAN4NFTD_CONF['socket'], $BAN4NFTD_CONF['socket_file']) == FALSE)
        {
            // エラーメッセージに、UNIXソケットとファイルがBINDできない旨を設定
            $ERR_MSG = 'Cannot bind socket'.'!?';
            // メッセージを表示
            print "\n".'ban4nftd ... '.$ERR_MSG."\n\n";
            // 終わり
            ban4nft_end(SIGTERM);
        }
        // UNIXソケットをノンブロッキングモードに変更できなかったら
        if (socket_set_nonblock($BAN4NFTD_CONF['socket']) == FALSE)
        {
            // エラーメッセージに、UNIXソケットをノンブロッキングモードに変更できない旨を設定
            $ERR_MSG = 'Cannot set non block socket'.'!?';
            // メッセージを表示
            print "\n".'ban4nftd ... '.$ERR_MSG."\n\n";
            // 終わり
            ban4nft_end(SIGTERM);
        }
        // UNIXソケットを配列に設定(読み込みできるかどうかだけ調べられればいいのでREAD_ARRAYに設定)
        $SOCK_READ_ARRAY = array($BAN4NFTD_CONF['socket']);
        $SOCK_WRITE_ARRAY  = NULL;
        $SOCK_EXCEPT_ARRAY = NULL;
        
        // 親プロセスの開始完了を出力
        $BAN4NFTD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: START under ".$BAN4NFTD_CONF['system_pid0']."\n";
        // ログに出力する
        log_write($BAN4NFTD_CONF);
        
        // 再読み込み要求(=1)が来るまで無限ループ(親プロセスがSIGHUPを受けると1)
        while($BAN4NFTD_CONF['reload'] == 0)
        {
            // 終わってしまった子プロセスのステータスを取得
            pcntl_wait($STATUS, WNOHANG);
            
            // UNIXソケットに変化が発生しているか(読み込みができるようになっているか)を取得、$BAN4NFTD_CONF['unbantime']だけ待つ
            // (socket_selectによって変数が上書きされるので常に設定)
            $READ_ARRAY = $SOCK_READ_ARRAY;
            $WRITE_ARRAY = $SOCK_WRITE_ARRAY;
            $EXCEPT_ARRAY = $SOCK_EXCEPT_ARRAY;
            $SOCK_RESULT = @socket_select($READ_ARRAY, $WRITE_ARRAY, $EXCEPT_ARRAY, $BAN4NFTD_CONF['unbantime']);
            // UNIXソケットの変化が取得できないなら
            if ($SOCK_RESULT === FALSE)
            {
                // 再読み込み要求(reload=1)ではないなら
                if ($BAN4NFTD_CONF['reload'] != 1)
                {
                    $BAN4NFTD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: ERROR "." Cannot socket_select!? (".socket_strerror(socket_last_error()).")"."\n";
                    // ログに出力する
                    log_write($BAN4NFTD_CONF);
                }
            }
            // UNIXソケットに変化がないなら
            else if ($SOCK_RESULT == 0)
            {
            }
            // 変化があるなら
            else if ($SOCK_RESULT > 0)
            {
                // ソケットからデータを受信して、ログメッセージに設定
                $SOCK_RESULT = socket_recvfrom($BAN4NFTD_CONF['socket'], $BAN4NFTD_CONF['log_msg'], 255, 0, $SOCK_FROM);
                // データの受信ができたなら
                if ($SOCK_RESULT != FALSE)
                {
                    // ログに出力する
                    log_write($BAN4NFTD_CONF);
                }
                // できなかったら
                else
                {
                    $BAN4NFTD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: ERROR "." Cannot socket_recvfrom!? (".socket_strerror(socket_last_error()).")"."\n";
                    // ログに出力する
                    log_write($BAN4NFTD_CONF);
                }
            }
            
            // 2021.09.07 T.Kabu どうもSQLite3が、DELETEの時にだけ何かのタイミングでデータベースがロックしているという判断でエラーとなる。実際にはDELETE出来ているので再試行も発生しないので、try/catchでスルーするようにした
            try {
                // カウントデータベースから最大カウント時間を過ぎたデータをすべて削除(いわゆる削除漏れのゴミ掃除)
                $SQL_STR = "DELETE FROM count_tbl WHERE registdate < ".$BAN4NFTD_CONF['maxfindtime'].";";
                $BAN4NFTD_CONF['count_db']->exec($SQL_STR);
            }
            catch (PDOException $PDO_E) {
                // エラーの旨メッセージを設定
                $BAN4NFTD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: WARN PDOException:".$PDO_E->getMessage()." on ".__FILE__.":".__LINE__."\n";
                // ログに出力する
                log_write($BAN4NFTD_CONF);
            }
            
            // BANデータベースでBAN解除対象IPアドレスを取得(UNIXタイム)
////            $SQL_STR = "SELECT * FROM ban_tbl WHERE unbandate < ".local_time().";";
            $SQL_STR = "SELECT * FROM ban_tbl WHERE unbandate < ".time().";";
            $RESULT = $BAN4NFTD_CONF['ban_db']->query($SQL_STR);
            // BAN解除対象IPアドレスの取得ができなかったら
            if ($RESULT === FALSE)
            {
                $BAN4NFTD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: ERROR "." Cannot query!? (".socket_strerror(socket_last_error()).")"."\n";
                // ログに出力する
                log_write($BAN4NFTD_CONF);
            }
            // BAN解除対象IPアドレスの取得ができたら
            else
            {
                // 該当データがあったらUNBANする
                while ($DB_DATA = $RESULT->fetch(PDO::FETCH_ASSOC))
                {
                    // UNBANする
                    $BAN4NFTD_CONF['target_address'] = $DB_DATA['address'];
                    $BAN4NFTD_CONF['target_service'] = $DB_DATA['service'];
                    $BAN4NFTD_CONF['target_protcol'] = $DB_DATA['protcol'];
                    $BAN4NFTD_CONF['target_port'] = $DB_DATA['port'];
                    $BAN4NFTD_CONF['target_rule'] = $DB_DATA['rule'];
                    $BAN4NFTD_CONF = ban4nft_unban($BAN4NFTD_CONF);
                    // ログに出力する
                    log_write($BAN4NFTD_CONF);
                }
                if (isset($TARGET_CONF['pdo_dsn_ban']) && preg_match('/^sqlite/', $TARGET_CONF['pdo_dsn_ban']))
                {
                    // WAL内のデータをDBに書き出し(こうしないとban4nftc listで確認したり、別プロセスでsqlite3ですぐに確認できない…が、負荷的にはWALにしている意味がないよなぁ…一応banの場合は発行時に、unbanはここですべてが終わった時に書き出し処理をする。count_dbはしない)
////                    $SQL_STR = "PRAGMA wal_checkpoint;";
////                    $BAN4NFTD_CONF['count_db']->exec($SQL_STR);
                    $SQL_STR = "PRAGMA wal_checkpoint;";
                    $BAN4NFTD_CONF['ban_db']->exec($SQL_STR);
                }
            }
            // 情報共有フラグがON(=1)なら
            if (isset($BAN4NFTD_CONF['iss_flag']) && $BAN4NFTD_CONF['iss_flag'] == 1)
            {
                // 情報共有サーバーからBAN情報を取得した最終日時からnnn秒経過したら
                if (($BAN4NFTD_CONF['iss_get_time'] = (time() - $BAN4NFTD_CONF['iss_last_time'])) > 180)
                {
                    $BAN4NFTD_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: INFO [iss-list] Request ISS Ban List "."\n";
                    // ログに出力する
                    log_write($BAN4NFTD_CONF);
                    // 情報共有サーバーのBANデータベースからBAN情報を取ってくる
                    issbanlistget($BAN4NFTD_CONF);
                    // 情報共有サーバーからBAN情報を取得した最終日時を設定
                    $BAN4NFTD_CONF['iss_last_time'] = time();
                }
            }
        }
        
        // シグナルハンドラをデフォルトに戻します(親プロセスだけ)
        pcntl_signal(SIGHUP,  SIG_DFL);
        pcntl_signal(SIGTERM, SIG_DFL);
        pcntl_signal(SIGINT,  SIG_DFL);
        
        unset($BAN4NFTD_CONF['proclist']);
    }
} while(1);
?>
