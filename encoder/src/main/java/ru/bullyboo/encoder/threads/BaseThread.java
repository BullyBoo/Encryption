package ru.bullyboo.encoder.threads;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.RunnableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;


/**
 * Created by BullyBoo on 30.03.2017.
 */

public abstract class BaseThread<T> extends Thread implements RunnableFuture<T> {

    private EncodeAction encodeAction;

    private ThreadCallback threadCallback;

    private volatile T result;

    public interface EncodeAction<T>{
        T action();
    }

    public interface ThreadCallback<T>{
        void onFinish(T parametr);

        void onFailed(Throwable e);
    }

    public BaseThread(EncodeAction<T> encodeAction, ThreadCallback<T> threadCallback) {
        super();
        this.encodeAction = encodeAction;
        this.threadCallback = threadCallback;
    }

    @Override
    public void run(){
        super.run();
        result = (T) encodeAction.action();

        interrupt();
    }

    @Override
    public void interrupt() {
        super.interrupt();
        try {
            threadCallback.onFinish(get());
        } catch (Exception e) {
            threadCallback.onFailed(e);
        }
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
        if(mayInterruptIfRunning){
            interrupt();
        }
        return mayInterruptIfRunning;
    }

    @Override
    public boolean isCancelled() {
        return interrupted();
    }

    @Override
    public boolean isDone() {
        if(result != null){
            return true;
        }
        return false;
    }

    @Override
    public T get() throws InterruptedException, ExecutionException {
        return result;
    }

    @Override
    public T get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        return result;
    }
}
