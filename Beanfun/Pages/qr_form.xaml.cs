using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace Beanfun
{
    /// <summary>
    /// qr_form.xaml 的交互逻辑
    /// </summary>
    public partial class qr_form : Page
    {
        public qr_form()
        {
            InitializeComponent();
        }

        private void btn_Refresh_QRCode_Click(object sender, RoutedEventArgs e)
        {
            App.MainWnd.refreshQRCode();
        }

        private void btn_CopyDeeplink_Click(object sender, RoutedEventArgs e)
        {
            var qrcodeClass = App.MainWnd.qrcodeClass;
            if (qrcodeClass != null && !string.IsNullOrEmpty(qrcodeClass.deeplink))
            {
                try
                {
                    Clipboard.SetText(qrcodeClass.deeplink);
                    MessageBox.Show(
                        Application.Current.TryFindResource("CopyDeeplinkSuccess") as string
                    );
                }
                catch
                {
                    MessageBox.Show(Application.Current.TryFindResource("CopyFailed") as string);
                }
            }
            else
            {
                MessageBox.Show(
                    Application.Current.TryFindResource("CopyDeeplinkNotReady") as string
                );
            }
        }

        private void btn_back_Click(object sender, RoutedEventArgs e)
        {
            App.LoginMethod = (int)LoginMethod.Regular;
            App.MainWnd.loginMethodChanged();
        }
    }
}
