package com.example.jj.hw;

import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Environment;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;

import com.example.jj.hw.BaseCrypto;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);



        Intent intent = getIntent();
        // String action = intent.getAction();
        // String type = intent.getType();
        ClipData clipData = intent.getClipData();
        String path = "";
        String sEncrypted = "";

        if (clipData != null && clipData.getItemCount() > 0) {
            ClipData.Item itm = clipData.getItemAt(0);

            if (itm.getUri() != null) {
                path = itm.getUri().toString();
                BaseCrypto encFile = new BaseCrypto();
                byte[] fileBytes;

                try {
                    String strRealPath = Environment.getExternalStorageDirectory().getPath();
                    fileBytes = IOUtil.readFile(strRealPath + "/DCIM/Camera/IMG_20150927_212926.jpg");
                    sEncrypted = encFile.encryptContent(Base64.encodeToString(fileBytes, Base64.DEFAULT), "password", "abcde0");
                    // fileBytes = IOUtil.readFile(strRealPath + "/DCIM/Camera/encrypted.jpg");

                    String sDecrypted = encFile.decryptContent(sEncrypted, "password", "abcde0");
                    byte[] decOut = Base64.decode(sDecrypted, Base64.DEFAULT);

                    // String encryptedBytes = x.encryptBytes(keyValue, "password", "abcde0");
                    // byte[] decryptedBytes = x.decryptBytes(encryptedBytes, "password", "abcde0");
                    // byte[] encryptedBytes = x.encryptBytes(fileBytes, "pass", "01aeb9ab");
                    // file:///storage/sdcard0/DCIM/Camera/IMG_20150927_212926.jpg

                    // now that the file is encrypted, write it to disk
                    BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(strRealPath + "/DCIM/Camera/decrypted.jpg"));
                    bos.write(decOut);
                    bos.flush();
                    bos.close();
                } catch (IOException ex) {
                    Log.i("YO", ex.toString());

                }

                Context context = getApplicationContext();
                CharSequence text = sEncrypted;
                int duration = Toast.LENGTH_LONG;

                Toast toast = Toast.makeText(context, text, duration);
                toast.show();
            }
        }

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "WOW", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
