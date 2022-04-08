// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef OPERATIONRESULT_H
#define OPERATIONRESULT_H

#include <util/translation.h>

class OperationResult
{
private:
    bool m_res{false};
    std::optional<bilingual_str> m_error{std::nullopt};

public:
    OperationResult(bool _res, const bilingual_str& _error) : m_res(_res), m_error(_error) { }
    OperationResult(bool _res) : m_res(_res) { }

    bilingual_str getError() const { return (m_error ? *m_error : bilingual_str()); }
    bool getRes() const { return m_res; }
    explicit operator bool() const { return m_res; }
};

inline OperationResult errorOut(const bilingual_str& errorStr)
{
    return OperationResult(false, errorStr);
}


template <class T>
class CallResult : public OperationResult
{
private:
    std::optional<T> m_obj_res{std::nullopt};
public:
    CallResult() : OperationResult(false) {}
    CallResult(T _obj) : OperationResult(true), m_obj_res(_obj) { }
    CallResult(const bilingual_str& error) : OperationResult(false, error) { }
    const std::optional<T>& getObjResult() const { return m_obj_res; }
};


#endif //OPERATIONRESULT_H