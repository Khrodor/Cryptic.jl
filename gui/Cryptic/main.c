#include <stdlib.h>
#include <gtk/gtk.h>
#include <julia.h>

void test2 (GtkWidget *wid, gpointer pt)
{
    jl_init_with_image("/home/student/julia/usr/lib/julia", "sys.so");

    /*jl_value_t *ret = jl_eval_string("sqrt(2.0)");

    if (jl_is_float64(ret)) {
        double ret_unboxed = jl_unbox_float64(ret);
        printf("sqrt(2.0) in C: %f \n", ret_unboxed);
    }*/

    jl_array_t *ret1 = jl_eval_string("Array{UInt8}(Vector{Char}(string(BigInt(2)^124)))");/*("Vector{Char}(string(BigInt(2)^124))");*/
    //("Array{Int8}(Vector{UInt8}(['a','b','c']))");
    JL_GC_PUSH1(&ret1);
    //char *xData = (char*)jl_array_data(ret1);
    //xData = (char*)jl_array_data(ret1);
    char *o = ret1;
    size_t i;
    for(i=0; i<jl_array_len(ret1); i++)
    {
        uint d = jl_array_data(ret1)+i+1;
        int8_t res1=jl_array_data(ret1)+i+1;
        uint8_t res2=jl_array_data(ret1)+i+1;
        char res = jl_array_data(ret1)+i+1;
        printf("value %d is %d \n", i, res);
    }
    JL_GC_POP();
    /*if (jl_is_int8(ret1)){
        int8_t* ret_unboxed1 = jl_unbox_int8(ret1);

        printf("string(BigInt(1)<<12) in C: %c \n", ret_unboxed1);
    }*/

    //*ret = jl_eval_string("string(BigInt(2)^128)");
    //printf("2^128 in C: %e \n", ret);

    jl_atexit_hook(0);
}

void createMenuItem(GtkWidget *wid){
}

int main (int argc, char *argv[])
{
    // Initialize Julia library
    //jl_init_with_image("/home/student/julia/usr/lib/julia", "sys.so");

    GtkWidget *window;
    GtkWidget *vbox;

    GtkWidget *menu_bar;
    GtkWidget *menu;
    GtkWidget *plik;
    GtkWidget *exit;
    GtkWidget *test;
    GtkWidget *etykieta1;

    gtk_init(&argc, &argv);

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
    gtk_window_set_default_size(GTK_WINDOW(window), 450, 100);
    gtk_window_set_title(GTK_WINDOW(window), "Cryptic");

    vbox = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(window), vbox);
    etykieta1 = gtk_label_new("Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
Maecenas sit amet magna in mi tincidunt iaculis sit amet quis augue. Curabitur libero est, \
vehicula vel consequat a, cursus sit amet risus. Nulla id eros arcu, sit amet dictum eros. \
Cras mollis, leo et dignissim bibendum, purus sapien interdum enim, ut.");
    gtk_label_set_line_wrap(GTK_LABEL(etykieta1), TRUE);

    menu_bar = gtk_menu_bar_new();
    menu = gtk_menu_new();

    plik = gtk_menu_item_new_with_mnemonic("_Plik");

    gtk_menu_item_set_submenu(GTK_MENU_ITEM(plik), menu);

    exit = gtk_image_menu_item_new_from_stock(GTK_STOCK_QUIT, NULL);
    gtk_image_menu_item_set_always_show_image (GTK_IMAGE_MENU_ITEM(exit), TRUE);

    test = gtk_image_menu_item_new_from_stock(GTK_STOCK_NEW, NULL);
    gtk_image_menu_item_set_always_show_image (GTK_IMAGE_MENU_ITEM(test), TRUE);

    gtk_menu_shell_append(GTK_MENU_SHELL(menu), test);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), exit);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu_bar), plik);
    gtk_box_pack_start(GTK_BOX(vbox), menu_bar, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(vbox), etykieta1, FALSE, FALSE, 3);

    g_signal_connect (G_OBJECT(window), "destroy", G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect (G_OBJECT(exit), "activate", G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect (G_OBJECT(test), "activate", G_CALLBACK(test2), (gpointer) window);

    gtk_widget_show_all(window);

    gtk_main();

    return 0;
}
