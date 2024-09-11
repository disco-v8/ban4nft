<?php
// ------------------------------------------------------------
// 
// BAN for nftables (Netfilter)
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
function ban4nft_unban($TARGET_CONF)
{
    // 対象IPアドレスを/で分割して配列に設定
    $TARGET_ADDRESS = explode("/", $TARGET_CONF['target_address']);
    // 対象IPアドレスがIPv6なら(IPv6だったら文字列そのものが返ってくる)
    if (filter_var($TARGET_ADDRESS[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE)
    {
        $IP_VER = 'ip6';
    }
    // 対象IPアドレスがIPv4なら(IPv4だったら文字列そのものが返ってくる)
    else if (filter_var($TARGET_ADDRESS[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
    {
        $IP_VER = 'ip';
    }
    // 対象IPアドレスがIPv4でもIPv6でもないなら
    else
    {
        // 対象IPアドレスはBANの対象だけど、アドレスがおかしい旨のメッセージを設定
        $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Ban ".$TARGET_CONF['target_address']." (over ".$TARGET_CONF['maxretry']." counts) ";
        $TARGET_CONF['log_msg'] .= 'Illegal address!?'."\n";
        // 2021.09.07 T.Kabu どうもSQLite3が、DELETEの時にだけ何かのタイミングでデータベースがロックしているという判断でエラーとなる。実際にはDELETE出来ているので再試行も発生しないので、try/catchでスルーするようにした
        try {
            // BANデータベースから対象IPアドレス(とポートとルールが合致するもの)を削除
            $TARGET_CONF['ban_db']->exec("DELETE FROM ban_tbl WHERE address = '".$TARGET_CONF['target_address']."' AND protcol = '".$TARGET_CONF['target_protcol']."' AND port = '".$TARGET_CONF['target_port']."' AND rule = '".$TARGET_CONF['target_rule']."'");
        }
        catch (PDOException $PDO_E) {
            // エラーの旨メッセージを設定
            $TARGET_CONF['log_msg'] .= date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: WARN PDOException:".$PDO_E->getMessage()." on ".__FILE__.":".__LINE__."\n";
        }
        // 戻る
        return $TARGET_CONF;
    }
    
    // 対象サービスについてBANのルール設定があるなら
    if (isset($TARGET_CONF['target_rule']))
    {
        // 対象サービスについてBANのプロトコルとポートがともに'all'なら
        if ($TARGET_CONF['target_protcol'] == 'all' && $TARGET_CONF['target_port'] == 'all')
        {
            // -----------------------------
            // ip6tablesに対象IPアドレスをBANするルールを設定する
            // -----------------------------
            // UNBANする前のコマンド(exec_befor_unban)が設定されていたら実行(UNBANする場合、すでにUNBAN済みでも実行)
            $TARGET_CONF = ban4nft_exec($TARGET_CONF, 'exec_befor_unban');
            
            // BAN4NFTチェインの設定を取得する
            $PROC_P = popen($TARGET_CONF['nft'].' -a list chain '.$IP_VER.' filter '.$TARGET_CONF['nft_chain'], "r");
            $TARGET_PATTERN = '/'.$IP_VER.' saddr '.preg_replace('/\//', '\/', $TARGET_CONF['target_address']).' '.strtolower($TARGET_CONF['target_rule']).' # handle (.*)$/';
            $TARGET_RESULT = psearch2($PROC_P, $TARGET_PATTERN);
            // BAN4NFTチェインに対象IPアドレスがあるなら
            if ($TARGET_RESULT != FALSE)
            {
                // BAN4NFTチェインから対象BANを削除する
                system($TARGET_CONF['nft'].' delete rule '.$IP_VER.' filter '.$TARGET_CONF['nft_chain'].' handle '.$TARGET_RESULT[1]);
                // 対象IPアドレスをUNBANした旨を出力
                $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Unban ".$TARGET_CONF['target_address'].' # handle '.$TARGET_RESULT[1]."\n";
            }
            else
            {
                // 対象IPアドレスがUNBANされている旨を出力
                $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Unbaned aleady ".$TARGET_CONF['target_address'].', or not found in rule'."\n";
            }
            pclose($PROC_P);
            
            // UNBANした後のコマンド(exec_afer_unban)が設定されていたら実行(UNBANする場合、すでにUNBAN済みでも実行)
            $TARGET_CONF = ban4nft_exec($TARGET_CONF, 'exec_after_unban');
        }
        // 対象サービスについてBANのプロトコルとポートが個別に設定されているなら
        else if (isset($TARGET_CONF['target_protcol']) && isset($TARGET_CONF['target_port']))
        {
            // -----------------------------
            // ip6tablesに対象IPアドレスをBANするルールを設定する
            // -----------------------------
            // UNBANする前のコマンド(exec_befor_unban)が設定されていたら実行(UNBANする場合、すでにUNBAN済みでも実行)
            $TARGET_CONF = ban4nft_exec($TARGET_CONF, 'exec_befor_unban');
            
            // BAN4NFTチェインの設定を取得する
            $PROC_P = popen($TARGET_CONF['nft'].' -a list chain '.$IP_VER.' filter '.$TARGET_CONF['nft_chain'], "r");
            $TARGET_PATTERN = '/'.$IP_VER.' saddr '.preg_replace('/\//', '\/', $TARGET_CONF['target_address']).' '.strtolower($TARGET_CONF['target_protcol']).' dport '.$TARGET_CONF['target_port'].' '.strtolower($TARGET_CONF['target_rule']).' # handle (.*)$/';
            $TARGET_RESULT = psearch2($PROC_P, $TARGET_PATTERN);
            // BAN4NFTチェインに対象IPアドレスがあるなら
            if ($TARGET_RESULT != FALSE)
            {
                // BAN4NFTチェインから対象BANを削除する
                system($TARGET_CONF['nft'].' delete rule '.$IP_VER.' filter '.$TARGET_CONF['nft_chain'].' handle '.$TARGET_RESULT[1]);
                // 対象IPアドレスをUNBANした旨を出力
                $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Unban ".$TARGET_CONF['target_address'].' # handle '.$TARGET_RESULT[1]."\n";
            }
            else
            {
                // 対象IPアドレスがUNBANされている旨を出力
                $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Unbaned aleady ".$TARGET_CONF['target_address'].', or not found in rule'."\n";
            }
            pclose($PROC_P);
            
            // UNBANした後のコマンド(exec_afer_unban)が設定されていたら実行(UNBANする場合、すでにUNBAN済みでも実行)
            $TARGET_CONF = ban4nft_exec($TARGET_CONF, 'exec_after_unban');
        }
        else
        {
            // 対象IPアドレスをUNBAN?した旨を出力
            $TARGET_CONF['log_msg'] = date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: NOTICE [".$TARGET_CONF['target_service']."] Unban? ".$TARGET_CONF['target_address']."\n";
        }
    }
    // 2021.09.07 T.Kabu どうもSQLite3が、DELETEの時にだけ何かのタイミングでデータベースがロックしているという判断でエラーとなる。実際にはDELETE出来ているので再試行も発生しないので、try/catchでスルーするようにした
    try {
        // BANデータベースから対象IPアドレス(とポートとルールが合致するもの)を削除
        $RESULT = $TARGET_CONF['ban_db']->exec("DELETE FROM ban_tbl WHERE address = '".$TARGET_CONF['target_address']."' AND protcol = '".$TARGET_CONF['target_protcol']."' AND port = '".$TARGET_CONF['target_port']."' AND rule = '".$TARGET_CONF['target_rule']."'");
    }
    catch (PDOException $PDO_E) {
        // エラーの旨メッセージを設定
        $TARGET_CONF['log_msg'] .= date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: WARN PDOException:".$PDO_E->getMessage()." on ".__FILE__.":".__LINE__."\n";
        $RESULT = TRUE;
    }
    // 削除できなかったら
    if ($RESULT === FALSE)
    {
        // delete_err_countの宣言がなかったら
        if (!isset($TARGET_CONF['delete_err_count']))
        {
            // 宣言をする
            $TARGET_CONF['delete_err_count'] = 0;
        }
        $TARGET_CONF['delete_err_count'] += 1;
        // もし検出回数以上になったら
        if ($TARGET_CONF['delete_err_count'] >= $TARGET_CONF['maxretry'])
        {
            // エラーの旨メッセージを設定
            $TARGET_CONF['log_msg'] .= date("Y-m-d H:i:s", local_time())." ban4nft[".getmypid()."]: WARN [".$TARGET_CONF['target_service']."] Cannot Query the DB, ".$TARGET_CONF['target_address']." ... DB File DELETE & REBOOT!(3)"."\n";
            // 親プロセスに送信…はしなくていい、unbanは親プロセスだから
            //ban4nft_sendmsg($TARGET_CONF);
            // ログに出力する(親プロセスにログを送信する代わりに)
            log_write($TARGET_CONF);
            // データベースファイルをリセット
            ban4nft_dbreset();
        }
    }
    // 戻る
    return $TARGET_CONF;
}
?>
