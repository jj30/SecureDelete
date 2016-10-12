package com.example.jj.hw;

import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Base64;
import android.util.DisplayMetrics;
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
import java.util.Random;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        Intent intent = getIntent();
        ClipData clipData = intent.getClipData();
        String path = "";
        String sEncrypted = "";

        if (clipData != null && clipData.getItemCount() > 0) {
            ClipData.Item itm = clipData.getItemAt(0);

            if (itm.getUri() != null) {
                path = itm.getUri().toString();
                path = getRealPathFromURI(this.getApplicationContext(), itm.getUri());
                BaseCrypto encFile = new BaseCrypto();
                byte[] fileBytes;

                try {
                    fileBytes = IOUtil.readFile(path);

                    // Get random password and salt. Default == 0.
                    String strRandomPW = getRandomPWSalt(16, Base64.DEFAULT);
                    String strRandomSalt = getRandomPWSalt(16, 1);
                    sEncrypted = encFile.encryptContent(Base64.encodeToString(fileBytes, Base64.DEFAULT), strRandomPW, strRandomSalt);
                    byte[] encOut = Base64.decode(sEncrypted, Base64.DEFAULT);

                    // now that the file is encrypted, write it to disk
                    BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(path));
                    bos.write(encOut);
                    bos.flush();
                    bos.close();

                    // Test code: am I encrypting correctly?
                    // String sDecrypted = encFile.decryptContent(sEncrypted, "password", "abcde0");
                } catch (IOException ex) {
                    Log.i("Secure Delete", ex.toString());
                }
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

    private String getRandomPWSalt(int numchars, int enc) {
        Random r = new Random();
        StringBuffer sb = new StringBuffer();
        while(sb.length() < numchars) {
            if (enc == Base64.DEFAULT) {
                byte[] rBytes = new byte[64];
                r.nextBytes(rBytes);
                sb.append(Base64.encodeToString(rBytes, Base64.DEFAULT));
            } else {
                sb.append(Integer.toHexString(r.nextInt()));
            }
        }

        return sb.toString().substring(0, numchars);
    }

    // http://stackoverflow.com/questions/19985286/convert-content-uri-to-actual-path-in-android-4-4
    private String getRealPathFromURI(Context context, Uri contentUri) {
        Cursor cursor = null;
        try {
            String[] proj = { MediaStore.Images.Media.DATA };
            cursor = context.getContentResolver().query(contentUri,  proj, null, null, null);
            int column_index = cursor.getColumnIndexOrThrow(MediaStore.Images.Media.DATA);
            cursor.moveToFirst();
            String path = cursor.getString(column_index);

            return path;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
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
