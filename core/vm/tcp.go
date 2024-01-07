package vm

import (
    "net"
    "net/http"
    "bufio"
    "io"

    "strings"
)

func sendCommandHttp(url string, command string) string {

    requestBody := strings.NewReader(command)

    resp, err := http.Post(url, "application/json", requestBody)
    if err != nil {
        return err.Error()
    }
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return err.Error()
    }
    bodys := string(body)
    resp.Body.Close()
    return bodys
}

func sendCommandTcp(url string, command string) string {
        // サーバーに接続
        conn, err := net.Dial("tcp", url)
        if err != nil {
            return err.Error()
        }
    
        // サーバーにコマンドを送信
        _, err = io.WriteString(conn, command+"\n");
        if err != nil {
            return err.Error()
        }
    
        // サーバーからの応答を受け取り表示
        response, err := bufio.NewReader(conn).ReadString('\n')
        if err != nil {
            return err.Error()
        }

        conn.Close()

        response = strings.ReplaceAll(response, "\n", "")
    
        return response
}
