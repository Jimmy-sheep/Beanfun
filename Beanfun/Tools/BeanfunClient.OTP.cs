using System;
using System.Collections.Specialized;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;

namespace Beanfun
{
    public partial class BeanfunClient : WebClient
    {
        public string GetOTP(
            ServiceAccount acc,
            string service_code = "610074",
            string service_region = "T9"
        )
        {
            try
            {
                string host;
                string loginHost;
                if (App.LoginRegion == "TW")
                {
                    host = "tw.beanfun.com";
                    loginHost = "tw.newlogin.beanfun.com";
                }
                else
                {
                    host = "bfweb.hk.beanfun.com";
                    loginHost = "login.hk.beanfun.com";
                }

                string pageUrl = $"https://{host}/beanfun_block/game_zone/game_start_step2.aspx?service_code={service_code}&service_region={service_region}&sotp={acc.ssn}&dt={GetCurrentTime(2)}";
                this.Headers.Set("Referer", $"https://{host}/");
                string response = this.DownloadString(pageUrl);

                if (string.IsNullOrEmpty(response))
                {
                    this.errmsg = "OTPNoResponse";
                    return null;
                }

                // Check for GGM m_objData handoff
                Match objMatch = Regex.Match(response, @"var\s+m_objData\s*=\s*\{(.*?)\};?", RegexOptions.Singleline);
                if (objMatch.Success)
                {
                    string block = objMatch.Groups[1].Value;
                    string sn = ExtractJsonStringField(block, "sn");
                    string launchData = ExtractJsonStringField(block, "data");
                    string handoffWebToken = ExtractJsonStringField(block, "webToken");
                    string handoffSecretCode = ExtractJsonStringField(block, "secretCode");

                    if (!string.IsNullOrEmpty(sn) && !string.IsNullOrEmpty(launchData))
                    {
                        // Best effort record service start
                        TryRecordServiceStart(host, acc, service_code, service_region, response);

                        ClientIntegrity integrity = ClientIntegrity.Resolve();
                        LaunchPayload payload = LaunchDataDecoder.Decode(launchData);

                        if (payload == null)
                        {
                            this.errmsg = "DecryptOTPError: Unable to decode launch data";
                            return null;
                        }

                        if (payload.Type == LaunchPayloadType.Ticket)
                        {
                            // Route A: POST to get_webstart_otp_v2.ashx (e.g. MapleStory)
                            return FetchOtpV2(host, pageUrl, sn, payload.LaunchTicket, integrity);
                        }
                        else if (payload.Type == LaunchPayloadType.Legacy)
                        {
                            // Route B: GET to get_webstart_otp.ashx with decoded parameters (e.g. CSO, Mabinogi)
                            string webToken = !string.IsNullOrEmpty(handoffWebToken) ? handoffWebToken : this.WebToken;
                            string secretCode = !string.IsNullOrEmpty(handoffSecretCode) ? handoffSecretCode : GetSecretCode(loginHost);

                            return FetchOtpLegacyWithHandoff(
                                host,
                                pageUrl,
                                sn,
                                webToken,
                                secretCode,
                                payload.LegacyParams,
                                integrity
                            );
                        }
                    }
                }

                // Fallback: Legacy flow without m_objData (e.g. HK region or older portal pages)
                return FetchOtpLegacyFlow(host, loginHost, acc, service_code, service_region, pageUrl, response);
            }
            catch (Exception e)
            {
                this.errmsg =
                    (System.Windows.Application.Current.TryFindResource("GetOtpError") as string)
                    + "\n\n"
                    + e.Message
                    + "\n"
                    + e.StackTrace;
                return null;
            }
        }

        private static string ExtractJsonStringField(string block, string fieldName)
        {
            Match match = Regex.Match(block, $@"""{fieldName}""\s*:\s*""([^""]*)""");
            if (match.Success)
            {
                return match.Groups[1].Value;
            }
            // Fallback for single-quoted or unquoted keys
            Match matchSingle = Regex.Match(block, $@"(?:""{fieldName}""|'{fieldName}'|{fieldName})\s*:\s*['""]([^'""]*)['""]");
            if (matchSingle.Success)
            {
                return matchSingle.Groups[1].Value;
            }
            return null;
        }

        private string FetchOtpV2(string host, string pageUrl, string sn, string launchTicket, ClientIntegrity integrity)
        {
            try
            {
                string v2Url = $"https://{host}/beanfun_block/generic_handlers/get_webstart_otp_v2.ashx";
                JObject requestObj = new JObject
                {
                    ["SN"] = sn,
                    ["LaunchTicket"] = launchTicket,
                    ["CV"] = integrity.CV,
                    ["Hash"] = integrity.Hash,
                    ["arch"] = integrity.Arch
                };

                this.Headers.Set("Referer", pageUrl);
                this.Headers.Set("Content-Type", "application/json; charset=utf-8");
                this.Headers.Set("Accept", "application/json, text/plain, */*");
                string responseText = base.UploadString(v2Url, "POST", requestObj.ToString(Newtonsoft.Json.Formatting.None));

                if (string.IsNullOrWhiteSpace(responseText))
                {
                    this.errmsg = "OTPNoResponse";
                    return null;
                }

                JObject responseObj = JObject.Parse(responseText);
                int result = responseObj["result"]?.Value<int>() ?? 0;
                if (result != 1)
                {
                    string serverMsg = responseObj["message"]?.ToString();
                    if (string.IsNullOrWhiteSpace(serverMsg))
                    {
                        serverMsg = $"result={result}";
                    }
                    this.errmsg = (System.Windows.Application.Current.TryFindResource("GetOtpError") as string)
                                  + "\r\n"
                                  + serverMsg;
                    return null;
                }

                string data = responseObj["data"]?.ToString();
                return DecryptOtpPayload(data);
            }
            catch (Exception ex)
            {
                this.errmsg = "FetchOtpV2 error: " + ex.Message;
                return null;
            }
        }

        private string FetchOtpLegacyWithHandoff(
            string host,
            string pageUrl,
            string sn,
            string webToken,
            string secretCode,
            LegacyOtpParams legacyParams,
            ClientIntegrity integrity
        )
        {
            try
            {
                string createTimeEncoded = Uri.EscapeDataString(legacyParams.CreateTime ?? "").Replace(" ", "%20");
                string queryUrl = $"https://{host}/beanfun_block/generic_handlers/get_webstart_otp.ashx"
                                  + $"?SN={sn}"
                                  + $"&WebToken={webToken}"
                                  + $"&SecretCode={secretCode}"
                                  + $"&ppppp={legacyParams.Ppppp}"
                                  + $"&ServiceCode={legacyParams.ServiceCode}"
                                  + $"&ServiceRegion={legacyParams.ServiceRegion}"
                                  + $"&ServiceAccount={legacyParams.ServiceAccount}"
                                  + $"&CreateTime={createTimeEncoded}"
                                  + $"&CV={integrity.CV}"
                                  + $"&Hash={integrity.Hash}"
                                  + $"&Arch={integrity.Arch}"
                                  + $"&d={Environment.TickCount}";

                this.Headers.Set("Referer", pageUrl);
                string response = this.DownloadString(queryUrl);
                return ParseAndDecryptLegacyResponse(response);
            }
            catch (Exception ex)
            {
                this.errmsg = "FetchOtpLegacyWithHandoff error: " + ex.Message;
                return null;
            }
        }

        private string FetchOtpLegacyFlow(
            string host,
            string loginHost,
            ServiceAccount acc,
            string service_code,
            string service_region,
            string pageUrl,
            string response
        )
        {
            Regex regex = new Regex("GetResultByLongPolling&key=(.*)\"");
            if (!regex.IsMatch(response))
            {
                this.errmsg = "OTPNoLongPollingKey:" + response;
                return null;
            }
            string longPollingKey = regex.Match(response).Groups[1].Value;

            string unkKey = null;
            string unkValue = null;
            if (App.LoginRegion == "TW")
            {
                regex = new Regex("MyAccountData.ServiceAccountCreateTime \\+ \"(.*)=(.*)\";");
                if (!regex.IsMatch(response))
                {
                    this.errmsg = "OTPNoUnkData";
                    return null;
                }
                unkKey = Uri.UnescapeDataString(regex.Match(response).Groups[1].Value);
                unkValue = Uri.UnescapeDataString(regex.Match(response).Groups[2].Value);
            }
            if (acc.screatetime == null)
            {
                regex = new Regex("ServiceAccountCreateTime: \"([^\"]+)\"");
                if (!regex.IsMatch(response))
                {
                    this.errmsg = "OTPNoCreateTime";
                    return null;
                }
                acc.screatetime = regex.Match(response).Groups[1].Value;
            }

            string secretCode = GetSecretCode(loginHost);
            if (string.IsNullOrEmpty(secretCode))
            {
                this.errmsg = "OTPNoSecretCode";
                return null;
            }

            NameValueCollection payload = new NameValueCollection();
            payload.Add("service_code", service_code);
            payload.Add("service_region", service_region);
            payload.Add("service_account_id", acc.sid);
            payload.Add("sotp", acc.ssn);
            payload.Add("service_account_display_name", acc.sname);
            payload.Add("service_account_create_time", acc.screatetime);
            if (unkKey != null && unkValue != null)
            {
                payload.Add(unkKey, unkValue);
            }

            System.Net.ServicePointManager.Expect100Continue = false;
            this.UploadString(
                $"https://{host}/beanfun_block/generic_handlers/record_service_start.ashx",
                payload
            );

            this.DownloadString(
                $"https://{host}/generic_handlers/get_result.ashx?meth=GetResultByLongPolling&key={longPollingKey}&_={GetCurrentTime()}"
            );

            string legacyUrl = $"https://{host}/beanfun_block/generic_handlers/get_webstart_otp.ashx?SN={longPollingKey}&WebToken={this.WebToken}&SecretCode={secretCode}&ppppp=1F552AEAFF976018F942B13690C990F60ED01510DDF89165F1658CCE7BC21DBA&ServiceCode={service_code}&ServiceRegion={service_region}&ServiceAccount={acc.sid}&CreateTime={acc.screatetime.Replace(" ", "%20")}&d={Environment.TickCount}";
            this.Headers.Set("Referer", pageUrl);
            string otpResponse = this.DownloadString(legacyUrl);

            return ParseAndDecryptLegacyResponse(otpResponse);
        }

        private string GetSecretCode(string loginHost)
        {
            try
            {
                string response = this.DownloadString(
                    $"https://{loginHost}/generic_handlers/get_cookies.ashx"
                );
                Regex regex = new Regex("var m_strSecretCode = '(.*)';");
                if (regex.IsMatch(response))
                {
                    return regex.Match(response).Groups[1].Value;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("GetSecretCode error: " + ex.Message);
            }
            return null;
        }

        private void TryRecordServiceStart(
            string host,
            ServiceAccount acc,
            string service_code,
            string service_region,
            string pageResponse
        )
        {
            try
            {
                string unkKey = null;
                string unkValue = null;
                if (App.LoginRegion == "TW")
                {
                    Regex regex = new Regex("MyAccountData.ServiceAccountCreateTime \\+ \"(.*)=(.*)\";");
                    if (regex.IsMatch(pageResponse))
                    {
                        unkKey = Uri.UnescapeDataString(regex.Match(pageResponse).Groups[1].Value);
                        unkValue = Uri.UnescapeDataString(regex.Match(pageResponse).Groups[2].Value);
                    }
                }
                if (acc.screatetime == null)
                {
                    Regex regex = new Regex("ServiceAccountCreateTime: \"([^\"]+)\"");
                    if (regex.IsMatch(pageResponse))
                    {
                        acc.screatetime = regex.Match(pageResponse).Groups[1].Value;
                    }
                }

                NameValueCollection payload = new NameValueCollection();
                payload.Add("service_code", service_code);
                payload.Add("service_region", service_region);
                payload.Add("service_account_id", acc.sid);
                payload.Add("sotp", acc.ssn);
                payload.Add("service_account_display_name", acc.sname);
                payload.Add("service_account_create_time", acc.screatetime ?? "");
                if (unkKey != null && unkValue != null)
                {
                    payload.Add(unkKey, unkValue);
                }

                System.Net.ServicePointManager.Expect100Continue = false;
                this.UploadString(
                    $"https://{host}/beanfun_block/generic_handlers/record_service_start.ashx",
                    payload
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine("TryRecordServiceStart error: " + ex.Message);
            }
        }

        private string ParseAndDecryptLegacyResponse(string response)
        {
            if (string.IsNullOrEmpty(response))
            {
                this.errmsg = "OTPNoResponse";
                return null;
            }
            string[] responses = response.Split(';');
            if (responses.Length < 2)
            {
                this.errmsg = "OTPNoResponse";
                return null;
            }
            if (responses[0] != "1")
            {
                this.errmsg =
                    (
                        System.Windows.Application.Current.TryFindResource("GetOtpError")
                        as string
                    )
                    + "\r\n"
                    + responses[1];
                return null;
            }

            return DecryptOtpPayload(responses[1]);
        }

        private string DecryptOtpPayload(string payload)
        {
            if (string.IsNullOrEmpty(payload) || payload.Length < 16)
            {
                this.errmsg = "DecryptOTPError: Invalid payload length";
                return null;
            }

            string key = payload.Substring(0, 8);
            string plain = payload.Substring(8);
            string otp = WCDESComp.DecryStrHex(plain, key);
            if (otp != null)
            {
                otp = otp.TrimEnd('\0');
                this.errmsg = null;
                return otp;
            }
            else
            {
                this.errmsg = "DecryptOTPError";
                return null;
            }
        }
    }
}
