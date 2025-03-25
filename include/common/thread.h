#ifndef THREAD_T
#define THREAD_T

#include <iostream>
#include <thread>

class _Thread{
public:

    template<typename Func, typename Obj, typename... Args> // lambda method to resolve obj function members and u_ptrs
    std::thread thread_create(Func Obj::*func, Obj &obj, Args&&... args) {
        return std::thread(
            [func, &obj, args_tuple = std::make_tuple(std::forward<Args>(args)...)]() mutable {
                std::apply([&obj, func](auto&&... unpackedArgs) {
                    (obj.*func)(std::forward<decltype(unpackedArgs)>(unpackedArgs)...);
                }, std::move(args_tuple));
            }
        );
    }

    // template<typename Func, typename... Args> //type safe, handles any type of function and arguments for function
    // std::thread thread_create(Func &&func, Args&&... arg){
    //     return std::thread(std::forward<Func>(func), std::forward<Args>(arg)...);
    // }
};
#endif