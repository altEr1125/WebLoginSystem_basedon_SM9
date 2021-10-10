package com.dommy.qrcode;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteDatabase.CursorFactory;

/**
 * @programName: DBOpenHelper.java
 * @programFunction: database helper class
 * @createDate: 2021/01/20
 * @author: gsy
 */
class DBOpenHelper extends SQLiteOpenHelper {
    public DBOpenHelper(Context context,String name, CursorFactory factory,
                        int version){
        super(context, name, factory, version);
    }

    @Override
    //首次创建数据库的时候调用，一般可以执行建库，建表的操作
    //Sqlite没有单独的布尔存储类型，它使用INTEGER作为存储类型，0为false，1为true
    public void onCreate(SQLiteDatabase db){
        //user table
        db.execSQL("create table if not exists user_tb(_id integer primary key autoincrement," +
                "userID text not null)");
    }

    @Override//当数据库的版本发生变化时，会自动执行
    public void onUpgrade(SQLiteDatabase db,int oldVersion,int newVersion){

    }
}