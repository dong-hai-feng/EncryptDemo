package com.ethan.encryptdemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity implements View.OnClickListener{
    TextView tv;
    private TextView show_text;
    private String publicEncryptedText,privateEncryptedText;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        tv = (TextView) findViewById(R.id.sample_text);
        tv.setText(jni.getInstance().stringFromJNI());
        show_text=(TextView) findViewById(R.id.show_text);

        initOnClick();
    }

    private void initOnClick() {
        findViewById(R.id.but_md5).setOnClickListener(this);
        findViewById(R.id.but_rsa_1).setOnClickListener(this);
        findViewById(R.id.but_rsa_2).setOnClickListener(this);
        findViewById(R.id.but_rsa_3).setOnClickListener(this);
        findViewById(R.id.but_rsa_4).setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()){
            case R.id.but_md5:
                show_text.setText(jni.getInstance().encrypt_MD5(tv.getText().toString()));
                break;
            case R.id.but_rsa_1:
                publicEncryptedText = jni.getInstance().encrypt_RSAbyPublicKey(tv.getText().toString());
                show_text.setText(publicEncryptedText);
                break;
            case R.id.but_rsa_2:
                show_text.setText(jni.getInstance().decrypt_RSAbyPrivateKey(publicEncryptedText));
                break;
            case R.id.but_rsa_3:
                privateEncryptedText=jni.getInstance().encrypt_RSAbyPrivateKey(tv.getText().toString());
                show_text.setText(privateEncryptedText);
                break;
            case R.id.but_rsa_4:
                show_text.setText(jni.getInstance().decrypt_RSAbyPublicKey(privateEncryptedText));
                break;
        }
    }
}
