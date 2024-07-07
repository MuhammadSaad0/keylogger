#include <WinSock2.h>
#include <Windows.h> // needed to access Windows System APIS
#include <stdio.h> // for io interaction
#include "sqlite3.h"
#include "mongoose.h"
#define BUFFER_SIZE 1024

HHOOK hook; // hook for a handle. A hook is a mechanism by which an application can intercept events, such as messages, mouse actions, and keystrokes.
sqlite3 *db;

typedef struct {
    char *json_str;
    size_t len;
} json_buffer_t;

// An application-defined or library-defined callback function used with the SetWindowsHookEx function. The system calls this function every time a 
// new keyboard input event is about to be posted into a thread input queue.
// Arguments: 1) nCode which tells us basically what to do, if it is 0 (HC_ACTION) then the second and third arguments
// contain data, 2) wParam is the identifier of the keyboard message, 3) lParam is pointer to a KBDLLHOOKSTRUCT structure.
// the KBDLLHOOKSTRUCT looks like this: 
// typedef struct tagKBDLLHOOKSTRUCT {
//  DWORD     vkCode;
//  DWORD     scanCode;
//  DWORD     flags;
//  DWORD     time;
//  ULONG_PTR dwExtraInfo;
// }
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam){
    if(nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT *kbd_ptr = (KBDLLHOOKSTRUCT *) lParam;
        if(wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            BYTE keyboard_state[256];
            // GetKeyboardState copies the status of the 256 virtual keys to the specified buffer.
            // useed to get info like CAPS LOCK
            GetKeyboardState(keyboard_state);

            wchar_t buffer[5];
            // ToUnicode converts the virtual key to unicode characters
            int result = ToUnicode(kbd_ptr->vkCode, kbd_ptr->scanCode, keyboard_state, buffer, 4, 0);
            buffer[result] = '\0';
            if(result > 0) {
                // wprintf(L"%ls", buffer);
                char insert_query[256]; // needs to have a size to make sure snprintf actually works
                char *zErrMsg = 0;
                int rc;
                // upsert
                snprintf(insert_query, sizeof(insert_query),"INSERT INTO CHARACTER_COUNTS(CHAR, COUNT) VALUES('%s', 1) ON CONFLICT(CHAR) DO UPDATE SET COUNT = COUNT + 1", buffer);
                rc = sqlite3_exec(db, insert_query, NULL, NULL, &zErrMsg);
               
            }
        }
        CallNextHookEx(hook, nCode, wParam, lParam);
    }
}

// Callback function for SQLite to format JSON response
static int json_callback(void *data, int argc, char **argv, char **azColName) {
    json_buffer_t *buffer = (json_buffer_t *)data;
    char temp[256];
    
    if (buffer->len == 0) {
        strcat(buffer->json_str, "[");
    } else {
        strcat(buffer->json_str, ",");
    }
    
    snprintf(temp, sizeof(temp), "{\"char\": \"%s\", \"count\": %s}", argv[0], argv[1]);
    strcat(buffer->json_str, temp);
    buffer->len += strlen(temp);

    return 0;
}

static void fn(struct mg_connection *c, int ev, void *ev_data){
    if(ev == MG_EV_HTTP_MSG){
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;  // Parsed HTTP request
        if(mg_match(hm->uri, mg_str("/get_counts"), NULL)){
            json_buffer_t buffer = {.json_str = malloc(BUFFER_SIZE), .len = 0};
            strcpy(buffer.json_str, "");  // Malloc does not initialize the allocated memory, strcpy is used  to ensure that buffer.json_str starts as an empty string
            char *query = "SELECT * FROM CHARACTER_COUNTS";
            char *zErrMsg = 0;
            int rc = sqlite3_exec(db, query, json_callback, (void *)&buffer, &zErrMsg); // callback function is run for each row
            
            if (rc != SQLITE_OK) {
              fprintf(stderr, "Error running select query: %s\n", zErrMsg);
              mg_http_reply(c, 500, "", "{%m:%d, %m:%m}\n", MG_ESC("status"), 500, MG_ESC("error"), MG_ESC("Error running select query"));
            } else {
              strcat(buffer.json_str, "]"); // close json if select went smoothly
              mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", buffer.json_str);
          }
        }else{
            struct mg_http_serve_opts opts = {.root_dir = "."};  
            mg_http_serve_dir(c, hm, &opts); 
        }  
    }
}

int main() {
    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    // a program executes within virtual memory space created by the OS when the program is loading.
    // The program itself and all of the dynamic link libraries loaded in the virtual memory space are called modules. 
    // The HMODULE, or HINSTANCE is the address within the virtual memory where the particular module is loaded
    // get the handle for the current module
    HINSTANCE h_instance = GetModuleHandle(NULL);

    // SetWindowsHookEx installs an application-defined hook procedure into a hook chain. 
    // You would install a hook procedure to monitor the system for certain types of events.
    // These events are associated either with a specific thread or with all threads in the same desktop as the calling thread.
    // the arguments are: 1) the type of hook procedure to install, we want to install a low level keyboard hook
    // to listen to keystrokes, 2) a pointer to the function you want to run as the hook procedure, this is the 
    // LowLevelKeyboardProc function provided by the windows api,
    // 3) a handle for which the hook procedure is to be run, 4) The identifier of
    // the thread with which the hook procedure is to be associated. For desktop apps, if this parameter is zero, the hook 
    // procedure is associated with all existing threads running in the same desktop as the calling thread.
    hook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, h_instance, 0);

    if(!hook) {
        printf("Error setting up hook!\n");
        exit(1);
    }

    MSG msg;

    char *zErrMsg = 0;
    int rc;

    rc = sqlite3_open("logger.db", &db);
    if(rc) {
        fprintf(stderr, "Cannot connect to sqlite\n", sqlite3_errmsg(db));
        exit(1);
    }else{
        fprintf(stderr, "Connected to sqlite\n");
    }
    char *create_table_query;
    create_table_query = "CREATE TABLE IF NOT EXISTS CHARACTER_COUNTS(CHAR TEXT PRIMARY KEY NOT NULL, COUNT INT)";
    rc = sqlite3_exec(db, create_table_query, NULL, 0, &zErrMsg);
    if(rc != SQLITE_OK){
        fprintf(stderr, "Error creating character counts tables: %s\n", zErrMsg);
        exit(1);
    }

    mg_http_listen(&mgr, "http://0.0.0.0:8000", fn, NULL);

    // old: GetMessage retrieves a message from the calling thread's message queue.
    // arguments are: 1) address of a MSG struct, 2) A handle to the window whose messages are to be retrieved. 
    // The window must belong to the current thread. If hWnd is NULL, GetMessage retrieves messages for any window 
    // that belongs to the current thread, and any messages on the current thread's message queue whose hwnd value is NULL,
    // 3) msgfiltermin if set to zero returns all messages without filtering, 4) msgfiltermax if set to zero returns all messages
    // without filtering, new: PeekMessage does the same thing as GetMessage but does not block
    for(;;){
        mg_mgr_poll(&mgr, 1);
        while(PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)){
            // Translates virtual-key messages into character messages. The character messages are posted to the calling thread's
            // message queue
            TranslateMessage(&msg);
            // Dispatches a message to a window procedure. The translated message will be passed to the hook procedure
            DispatchMessage(&msg);
        }
    }

    sqlite3_close(db);
    UnhookWindowsHookEx(hook);

    return 0;

}